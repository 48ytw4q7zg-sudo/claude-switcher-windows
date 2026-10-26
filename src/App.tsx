import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import {
  Archive,
  Activity,
  BarChart3,
  CheckCircle2,
  ClipboardCopy,
  Clock,
  Database,
  ExternalLink,
  EyeOff,
  FileKey,
  FileText,
  Fingerprint,
  History,
  Loader2,
  Minimize2,
  Network,
  Plus,
  Power,
  RefreshCw,
  Router,
  RotateCcw,
  ShieldAlert,
  Trash2,
  UserRound,
} from 'lucide-react';
import { ClaudeTrayPopup } from './components/ClaudeTrayPopup';

const WINDOW_LABEL = (() => {
  if (new URLSearchParams(window.location.search).get('window') === 'tray-popup') {
    return 'tray-popup';
  }
  try {
    return getCurrentWebviewWindow().label;
  } catch {
    return 'main';
  }
})();

type Platform = 'windows' | 'macos' | 'linux';

// 平台检测走 Rust get_platform（cfg! 结果），替代已弃用的 navigator.platform。
// 初值用 navigator 猜一份（SSR/首帧渲染用），get_platform 返回后校正。
const detectPlatformFromUA = (): Platform => {
  try {
    if (/win/i.test(navigator.userAgent)) return 'windows';
    if (/macintosh|mac os x/i.test(navigator.userAgent)) return 'macos';
  } catch {
    /* navigator 不可用时回退 linux */
  }
  return 'linux';
};

interface ProfileMeta {
  email?: string | null;
  account_uuid?: string | null;
  organization_uuid?: string | null;
  organization_name?: string | null;
  user_id_hash?: string | null;
  has_oauth_account: boolean;
  has_keychain_credentials: boolean;
  has_trusted_device_token: boolean;
  subscription_type?: string | null;
  rate_limit_tier?: string | null;
}

interface ProfileSummary {
  id: string;
  name: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  last_switched_at?: string | null;
  meta: ProfileMeta;
  clash?: ProfileClashBinding | null;
  runtime?: ProfileRuntimeBinding | null;
  is_current: boolean;
}

interface ProfileClashBinding {
  enabled: boolean;
  group: string;
  node: string;
}

interface ProfileRuntimeBinding {
  timezone?: string | null;
  locale?: string | null;
  chrome_profile?: string | null;
}

interface ClaudeStatus {
  claude_json_exists: boolean;
  settings_json_exists: boolean;
  credentials_json_exists: boolean;
  keychain_exists: boolean;
  keychain_parse_ok: boolean;
  meta: ProfileMeta;
  claude_json_path: string;
  settings_json_path: string;
  data_dir: string;
  backup_dir: string;
  session_isolation: SessionIsolationStatus;
  profile_count: number;
  current_profile_id?: string | null;
  current_profile_name?: string | null;
  pending_new_account?: PendingNewAccount | null;
  warnings: string[];
  telemetry_mode: TelemetryMode;
}

interface SessionIsolationStatus {
  enabled: boolean;
  live_path: string;
  target_path?: string | null;
  current_profile_path?: string | null;
  link_mode?: string;
  degraded?: boolean;
}

interface PendingNewAccount {
  id: string;
  name: string;
  notes?: string | null;
  group: string;
  node: string;
  runtime: ProfileRuntimeBinding;
  created_at: string;
}

interface BackupResult {
  id: string;
  path: string;
  created_at: string;
}

interface SwitchResult {
  switched_to: string;
  backup: BackupResult;
  clash?: ClashSwitchResult | null;
  restart_hint: string;
  warnings: string[];
}

interface PrepareNewAccountResult {
  pending: PendingNewAccount;
  backup: BackupResult;
  clash: ClashSwitchResult;
  warnings: string[];
}

interface RestoreResult {
  restored_from: string;
  warnings: string[];
}

interface BackupSummary {
  id: string;
  label: string;
  created_at: string;
}

interface ClashStatus {
  available: boolean;
  controller: string;
  group: string;
  group_type?: string | null;
  now?: string | null;
  nodes: string[];
  error?: string | null;
}

interface ClashSwitchResult {
  group: string;
  node: string;
  previous?: string | null;
  verified: boolean;
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

interface DailyUsage {
  date: string;
  totals: TokenTotals;
  message_count: number;
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
  daily: DailyUsage[];
  top_model?: string | null;
  warnings: string[];
}

const usageFallback = (warning: string): ClaudeUsageSnapshot => ({
  updated_at: new Date().toISOString(),
  scanned_files: 0,
  scanned_messages: 0,
  latest_message_at: null,
  session: { label: '近 5 小时', totals: emptyTotals(), message_count: 0, reset_at: null },
  weekly: { label: '近 7 天', totals: emptyTotals(), message_count: 0, reset_at: null },
  today: { label: '今天', totals: emptyTotals(), message_count: 0, reset_at: null },
  last_30_days: { label: '近 30 天', totals: emptyTotals(), message_count: 0, reset_at: null },
  daily: [],
  top_model: null,
  warnings: [warning],
});

const withTimeout = async <T,>(promise: Promise<T>, ms: number, label: string): Promise<T> => {
  let timer: number | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = window.setTimeout(() => reject(new Error(`${label} 超时`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) window.clearTimeout(timer);
  }
};

const nextAnimationFrame = () =>
  new Promise<void>((resolve) => {
    window.requestAnimationFrame(() => resolve());
  });

type BusyAction =
  | 'refresh'
  | 'capture'
  | 'new-login'
  | 'finish-new'
  | 'switch'
  | 'backup'
  | 'delete'
  | 'bind'
  | 'clash'
  | 'list-backups'
  | 'restore'
  | 'telemetry'
  | 'autostart'
  | null;

type NewAccountModalState = 'draft' | 'running' | 'done';

// 遥测去关联：三态。后端按这些字符串向 settings.env 注入 / 清理隐私 env。
type TelemetryMode = 'default' | 'disableTelemetry' | 'essentialOnly';

const TELEMETRY_OPTIONS: {
  value: TelemetryMode;
  label: string;
  badge?: string;
  desc: string;
}[] = [
  {
    value: 'default',
    label: '关闭',
    desc: '不注入任何隐私 env，保持 Claude Code 默认行为（遥测照常上报）。',
  },
  {
    value: 'disableTelemetry',
    label: '去关联',
    badge: '推荐',
    desc: '注入 DISABLE_TELEMETRY=1，关闭会把同设备多账号关联起来的遥测（Datadog / 事件 / GrowthBook），副作用极小。',
  },
  {
    value: 'essentialOnly',
    label: '最强',
    desc: '注入 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1，关掉一切非必要流量。',
  },
];

const fmt = new Intl.DateTimeFormat('zh-CN', {
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

function shortId(value?: string | null) {
  if (!value) return '未发现';
  if (value.includes('@')) {
    const [name, domain] = value.split('@');
    return `${name.slice(0, 2)}***@${domain}`;
  }
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function statusAccountLabel(status?: ClaudeStatus | null) {
  if (status?.pending_new_account) return `待登录：${status.pending_new_account.name}`;
  return status?.meta.email ? shortId(status.meta.email) : status?.current_profile_name || '未发现';
}

function statusOrganizationLabel(status?: ClaudeStatus | null) {
  if (status?.pending_new_account) return '等待手动完成 Claude Code OAuth';
  return status?.meta.organization_name || '未读取到组织名';
}

function dateLabel(value?: string | null) {
  if (!value) return '从未';
  return fmt.format(new Date(value));
}

function relativeTime(value?: string | null) {
  if (!value) return '无记录';
  const diff = new Date(value).getTime() - Date.now();
  const abs = Math.abs(diff);
  const minutes = Math.round(abs / 60000);
  if (minutes < 1) return diff >= 0 ? '马上' : '刚刚';
  if (minutes < 60) return diff >= 0 ? `${minutes} 分钟后` : `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return diff >= 0 ? `${hours} 小时后` : `${hours} 小时前`;
  const days = Math.round(hours / 24);
  return diff >= 0 ? `${days} 天后` : `${days} 天前`;
}

function compactNumber(value?: number | null) {
  const next = value ?? 0;
  if (next >= 1_000_000_000) return `${(next / 1_000_000_000).toFixed(next >= 10_000_000_000 ? 0 : 1)}B`;
  if (next >= 1_000_000) return `${(next / 1_000_000).toFixed(next >= 10_000_000 ? 0 : 1)}M`;
  if (next >= 1_000) return `${(next / 1_000).toFixed(next >= 10_000 ? 0 : 1)}K`;
  return `${next}`;
}

function usagePercent(window: UsageWindow | undefined, max: number) {
  if (!window || max <= 0) return 0;
  if (typeof window.used_percent === 'number') {
    return Math.max(3, Math.min(100, 100 - window.used_percent));
  }
  return Math.max(3, Math.min(100, (window.totals.total_tokens / max) * 100));
}

function usageLabel(window?: UsageWindow | null) {
  if (typeof window?.used_percent === 'number') {
    return `${Math.round(Math.max(0, Math.min(100, 100 - window.used_percent)))}% 剩余`;
  }
  return `${compactNumber(window?.totals.total_tokens)} token`;
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return <span className={ok ? 'pill ok' : 'pill muted'}>{label}</span>;
}

function Field({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="field">
      <span>{label}</span>
      <strong>{value || '未发现'}</strong>
    </div>
  );
}

function StatusIcon({
  ok,
  label,
  detail,
}: {
  ok: boolean;
  label: string;
  detail: string;
}) {
  return (
    <div className={ok ? 'status-icon ok' : 'status-icon warn'}>
      <span>{ok ? <CheckCircle2 /> : <ShieldAlert />}</span>
      <div>
        <strong>{label}</strong>
        <em>{detail}</em>
      </div>
    </div>
  );
}

function UsageRow({ item, max }: { item: UsageWindow; max: number }) {
  return (
    <div className="usage-row">
      <div className="usage-row-head">
        <strong>{item.label}</strong>
        <span>{usageLabel(item)}</span>
      </div>
      <div className="usage-bar">
        <span style={{ width: `${usagePercent(item, max)}%` }} />
      </div>
      <div className="usage-row-foot">
        <span>{compactNumber(item.totals.total_tokens)} token · {item.message_count} 条 usage</span>
        <span>{item.reset_at ? `${relativeTime(item.reset_at)}重置` : '无重置估算'}</span>
      </div>
    </div>
  );
}

function emptyTotals(): TokenTotals {
  return {
    input_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
  };
}

function fallbackWindow(label: string): UsageWindow {
  return {
    label,
    totals: emptyTotals(),
    message_count: 0,
    reset_at: null,
  };
}

function App() {
  if (WINDOW_LABEL === 'tray-popup') {
    return <ClaudeTrayPopup />;
  }

  const [status, setStatus] = useState<ClaudeStatus | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [usage, setUsage] = useState<ClaudeUsageSnapshot | null>(null);
  const [name, setName] = useState('');
  const [notes, setNotes] = useState('');
  const [newAccountName, setNewAccountName] = useState('尼区');
  const [newAccountNotes, setNewAccountNotes] = useState('');
  const [newAccountNode, setNewAccountNode] = useState('');
  const [newAccountTimezone, setNewAccountTimezone] = useState('Africa/Lagos');
  const [newAccountLocale, setNewAccountLocale] = useState('en_US.UTF-8');
  const [newAccountChromeProfile, setNewAccountChromeProfile] = useState('Profile 4');
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [usageRefreshing, setUsageRefreshing] = useState(false);
  const [clashStatus, setClashStatus] = useState<ClashStatus | null>(null);
  const [actionWarnings, setActionWarnings] = useState<string[]>([]);
  const [backups, setBackups] = useState<BackupSummary[]>([]);
  const [telemetryMode, setTelemetryMode] = useState<TelemetryMode | null>(null);
  const [newAccountModalOpen, setNewAccountModalOpen] = useState(false);
  const [newAccountModalState, setNewAccountModalState] = useState<NewAccountModalState>('draft');
  const [newAccountProgress, setNewAccountProgress] = useState(0);
  const [currentWorkNote, setCurrentWorkNote] = useState('');
  const [newAccountStep, setNewAccountStep] = useState('等待确认');
  const [platform, setPlatform] = useState<Platform>(detectPlatformFromUA);
  const [autostart, setAutostart] = useState(false);
  const [autostartDisabled, setAutostartDisabled] = useState(false);
  const [claudeConfigDir, setClaudeConfigDir] = useState('');
  const [claudeConfigOverride, setClaudeConfigOverride] = useState('');

  const credentialLabel = platform === 'windows' ? '凭据文件' : 'Keychain';
  const credentialFullText = platform === 'windows' ? '.credentials.json 登录态' : '钥匙串登录态';

  useEffect(() => {
    // Rust 侧 cfg! 结果回来后校正平台（navigator.platform 已弃用）。
    invoke<Platform>('get_platform')
      .then((next) => setPlatform(next))
      .catch(() => undefined);
    // 开机自启当前状态（仅 Windows 有意义）。返回三态：注册与否 + 是否被用户在
    // 任务管理器禁用——只看 Run 值会把「已禁用」误显示成开启。
    invoke<{ registered: boolean; disabled_by_user: boolean }>('get_autostart')
      .then((next) => {
        setAutostart(next.registered && !next.disabled_by_user);
        setAutostartDisabled(next.disabled_by_user);
      })
      .catch(() => undefined);
    invoke<string>('get_claude_config_dir')
      .then((next) => setClaudeConfigDir(next))
      .catch(() => undefined);
    // 覆盖框初始为空（而不是预填解析后的目录）：否则用户一点保存，
    // 就会把默认路径固化成覆盖文件，之后再改环境变量也不再跟随。
    invoke<Option<string>>('get_claude_config_dir_override')
      .then((next) => setClaudeConfigOverride(next ?? ''))
      .catch(() => undefined);
  }, []);

  const currentProfile = useMemo(
    () => profiles.find((profile) => profile.is_current) || null,
    [profiles],
  );

  useEffect(() => {
    if (newAccountNode || !clashStatus?.nodes.length) return;
    const preferred =
      clashStatus.nodes.find((node) => node === '南非-B') ||
      clashStatus.nodes.find((node) => node.includes('南非')) ||
      '';
    if (preferred) setNewAccountNode(preferred);
  }, [clashStatus?.nodes, newAccountNode]);

  useEffect(() => {
    const text = `${newAccountName} ${newAccountNode}`.toLowerCase();
    if (text.includes('尼') || text.includes('nigeria') || text.includes('南非')) {
      setNewAccountTimezone('Africa/Lagos');
      setNewAccountLocale('en_US.UTF-8');
      setNewAccountChromeProfile('Profile 4');
    } else if (text.includes('美') || text.includes('us') || text.includes('38')) {
      setNewAccountTimezone('America/Los_Angeles');
      setNewAccountLocale('en_US.UTF-8');
      setNewAccountChromeProfile('Profile 35');
    }
  }, [newAccountName, newAccountNode]);

  const refreshUsage = useCallback(async () => {
    setUsageRefreshing(true);
    try {
      await nextAnimationFrame();
      const nextUsage = await withTimeout(
        invoke<ClaudeUsageSnapshot>('get_claude_usage'),
        8000,
        'Claude 用量刷新',
      ).catch((err) => usageFallback(String(err)));
      setUsage(nextUsage);
    } finally {
      setUsageRefreshing(false);
    }
  }, []);

  const load = useCallback(async () => {
    setBusy('refresh');
    setError(null);
    try {
      const [nextStatus, nextProfiles, nextBackups] = await Promise.all([
        invoke<ClaudeStatus>('get_status'),
        invoke<ProfileSummary[]>('list_profiles'),
        invoke<BackupSummary[]>('list_backups'),
      ]);
      setStatus(nextStatus);
      setProfiles(nextProfiles);
      setBackups(nextBackups);

      // 遥测模式：get_status 始终带 telemetry_mode（后端非 Option 字段）。
      setTelemetryMode(nextStatus.telemetry_mode);
    } catch (err) {
      setError(String(err));
      return;
    } finally {
      // 主数据已就绪：立刻解除 busy，让按钮可用（用量/Clash 是渐进加载）。
      setBusy(null);
    }

    // 用量与 Clash 状态并行拉取；合进 await 链，避免游离 promise
    // 在后续 load() 之后落地而显示过期数据。
    const [nextUsage, nextClashStatus] = await Promise.all([
      withTimeout(invoke<ClaudeUsageSnapshot>('get_claude_usage'), 8000, 'Claude 用量刷新').catch(
        (err) => usageFallback(String(err)),
      ),
      withTimeout(invoke<ClashStatus>('get_clash_status'), 6000, 'Clash 状态刷新').catch((err) => ({
        available: false,
        controller: 'http://127.0.0.1:9090',
        group: 'Auto-Claude',
        nodes: [],
        error: String(err),
      })),
    ]);
    setUsage(nextUsage);
    setClashStatus(nextClashStatus);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: BusyAction, fn: () => Promise<string | void>) => {
    setBusy(action);
    setError(null);
    try {
      const message = await fn();
      if (message) setToast(message);
      // 操作已经成功；refresh 失败不应把结果显示成错误（否则用户以为操作失败会重试）。
      // load() 内部会 setError，这里吞掉异常即可。
      await load().catch(() => undefined);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const capture = () =>
    run('capture', async () => {
      await invoke('capture_current_profile', {
        name: name.trim(),
        notes: notes.trim() || null,
      });
      setName('');
      setNotes('');
      return '已保存当前 Claude Code 账号快照';
    });

  const openPrepareNewAccountModal = () => {
    setCurrentWorkNote('');
    setNewAccountProgress(0);
    setNewAccountStep('等待确认');
    setNewAccountModalState('draft');
    setNewAccountModalOpen(true);
  };

  const closePrepareNewAccountModal = () => {
    if (newAccountModalState === 'running') return;
    setNewAccountModalOpen(false);
  };

  const prepareNewAccount = async () => {
    setBusy('new-login');
    setError(null);
    setActionWarnings([]);
    setNewAccountModalState('running');
    setNewAccountProgress(8);
    setNewAccountStep('记录当前工作');
    try {
      await nextAnimationFrame();
      const noteParts = [
        newAccountNotes.trim(),
        currentWorkNote.trim() ? `切号前正在处理: ${currentWorkNote.trim()}` : '',
      ].filter(Boolean);
      setNewAccountProgress(22);
      setNewAccountStep('保存当前账号状态');
      await nextAnimationFrame();
      setNewAccountProgress(38);
      setNewAccountStep(`切换 Auto-Claude 到 ${newAccountNode}`);
      const result = await invoke<PrepareNewAccountResult>('prepare_new_account_login', {
        name: newAccountName.trim(),
        notes: noteParts.join('\n\n') || null,
        node: newAccountNode,
        timezone: newAccountTimezone.trim() || null,
        locale: newAccountLocale.trim() || null,
        chromeProfile: newAccountChromeProfile.trim() || null,
      });
      setNewAccountProgress(88);
      setNewAccountStep('环境已准备，等待手动授权');
      setActionWarnings([]);
      setActionWarnings(result.warnings ?? []);
      setToast(`已准备新号「${result.pending.name}」环境；Auto-Claude 已切到 ${result.clash.node}`);
      // 先把成功状态落定，再刷新界面：
      // load() 失败不应把已经准备好的流程误判成「准备失败」——
      // 那样用户会重试，而后端会以「已有待完成流程」拒绝，流程卡死。
      setNewAccountProgress(100);
      setNewAccountStep('完成。请确认 IP 后手动打开 Claude Code 授权');
      setNewAccountModalState('done');
      await load().catch(() => undefined);
    } catch (err) {
      setError(String(err));
      setNewAccountStep('准备失败，请看错误提示');
      setNewAccountModalState('draft');
      setNewAccountProgress(0);
    } finally {
      setBusy(null);
    }
  };

  const finishNewAccount = () =>
    run('finish-new', async () => {
      await invoke<ProfileSummary>('complete_new_account_login');
      setNewAccountName('尼区');
      setNewAccountNotes('');
      setNewAccountNode('');
      setNewAccountTimezone('Africa/Lagos');
      setNewAccountLocale('en_US.UTF-8');
      setNewAccountChromeProfile('Profile 4');
      return '新号已保存并绑定节点';
    });

  const cancelNewAccount = () => {
    if (!window.confirm('取消这次新号登录流程，并切回当前保存的账号快照？')) return;
    run('switch', async () => {
      setActionWarnings([]);
      const result = await invoke<SwitchResult | null>('cancel_pending_new_account_login');
      setActionWarnings(result?.warnings ?? []);
      return result
        ? `已取消新号流程，并切回 ${result.switched_to}`
        : '已取消新号流程';
    });
  };

  const switchTo = (id: string) =>
    run('switch', async () => {
      setActionWarnings([]);
      const result = await invoke<SwitchResult>('switch_profile', { id });
      setActionWarnings(result.warnings ?? []);
      const clash = result.clash
        ? `Auto-Claude 已切到 ${result.clash.node}；`
        : '';
      return `${result.switched_to} 已切换；${clash}${result.restart_hint}`;
    });

  const loadBackups = useCallback(async () => {
    const next = await invoke<BackupSummary[]>('list_backups');
    setBackups(next);
  }, []);

  const refreshBackups = () =>
    run('list-backups', async () => {
      await loadBackups();
    });

  const backup = () =>
    run('backup', async () => {
      const result = await invoke<BackupResult>('create_backup');
      await loadBackups().catch(() => undefined);
      return `备份已写入 ${result.path}`;
    });

  const restore = (id: string, label: string) => {
    if (
      !window.confirm(
        `完整还原到备份「${label}」？\n\n会用该备份覆盖当前 ~/.claude.json、settings.json 和${credentialFullText}；备份中缺失的项会被删除 / 清空。\n还原前会自动创建一次 before-restore 备份以便回滚。`,
      )
    )
      return;
    run('restore', async () => {
      setActionWarnings([]);
      const result = await invoke<RestoreResult>('restore_backup', { id });
      setActionWarnings(result.warnings ?? []);
      return `已从 ${result.restored_from} 恢复`;
    });
  };

  const remove = (id: string, label: string) => {
    if (!window.confirm(`删除账号快照「${label}」？这不会删除 Claude Code 当前登录。`)) return;
    run('delete', async () => {
      await invoke('delete_profile', { id });
      return '账号快照已删除';
    });
  };

  const bindNode = (id: string, node: string) =>
    run('bind', async () => {
      await invoke('set_profile_clash_binding', {
        id,
        enabled: node.length > 0,
        group: 'Auto-Claude',
        node,
      });
      return node ? `已绑定 Auto-Claude -> ${node}` : '已清除这个账号的节点绑定';
    });

  const bindRuntime = (profile: ProfileSummary, patch: Partial<ProfileRuntimeBinding>) =>
    run('bind', async () => {
      const next = { ...(profile.runtime ?? {}), ...patch };
      await invoke('set_profile_runtime_binding', {
        id: profile.id,
        timezone: next.timezone || null,
        locale: next.locale || null,
        chromeProfile: next.chrome_profile || null,
      });
      return '已保存账号环境绑定';
    });

  const testProfileNode = (id: string) =>
    run('clash', async () => {
      const result = await invoke<ClashSwitchResult>('switch_profile_clash_node', { id });
      return result.verified
        ? `Auto-Claude 已切到 ${result.node}`
        : `已请求切到 ${result.node}，但 Clash 当前状态未确认`;
    });

  const openDataDir = () =>
    run(null, async () => {
      await invoke('open_data_dir');
    });

  const [includeNetwork, setIncludeNetwork] = useState(false);

  /// 收集诊断信息并复制到剪贴板。默认只做本地检查（不发网络请求），
  /// 勾选后再查 Clash 与 OAuth——断网时也不会卡住界面。
  const copyDiagnostics = () =>
    run(null, async () => {
      const info = await invoke<Record<string, unknown>>('get_diagnostic_info', {
        includeNetwork,
      });
      const text = JSON.stringify(info, null, 2);
      try {
        await navigator.clipboard.writeText(text);
        return '诊断信息已复制到剪贴板';
      } catch {
        // 剪贴板不可用（权限/非 HTTPS）时退回显示，让用户手动复制。
        return `剪贴板不可用，请手动复制：\n${text}`;
      }
    });

  const applyTelemetryMode = (mode: TelemetryMode) => {
    if (mode === telemetryMode) return;
    run('telemetry', async () => {
      await invoke('set_telemetry_mode', { mode });
      const label = TELEMETRY_OPTIONS.find((o) => o.value === mode)?.label ?? mode;
      return `遥测去关联已切到「${label}」`;
    });
  };

  const canCapture = name.trim().length > 0 && !busy;
  const canPrepareNewAccount =
    newAccountName.trim().length > 0 && newAccountNode.length > 0 && !busy && !status?.pending_new_account;
  const canFinishNewAccount = !!status?.pending_new_account && !busy;
  const usageMax = Math.max(
    usage?.session.totals.total_tokens ?? 0,
    usage?.weekly.totals.total_tokens ?? 0,
    usage?.today.totals.total_tokens ?? 0,
    usage?.last_30_days.totals.total_tokens ?? 0,
    1,
  );
  const dailyMax = Math.max(...(usage?.daily ?? []).map((item) => item.totals.total_tokens), 1);

  return (
    <main className="app">
      <section className="header">
        <div>
          <div className="eyebrow">Claude Code Local Account Switcher</div>
          <h1>账号快照控制台</h1>
        </div>
        <div className="header-actions">
          <button className="ghost" onClick={() => load()} disabled={!!busy}>
            {busy === 'refresh' ? <Loader2 className="spin" /> : <RefreshCw />}
            刷新
          </button>
          <button className="ghost" onClick={backup} disabled={!!busy}>
            <Archive />
            手动备份
          </button>
          <button
            className="ghost"
            onClick={() => invoke('hide_main_window_cmd')}
            disabled={!!busy}
            title="关闭窗口会隐藏到托盘，不会退出程序"
          >
            <Minimize2 />
            隐藏到托盘
          </button>
          <button
            className="ghost danger"
            onClick={() => {
              if (window.confirm('退出 Claude Switcher？账号快照与备份都会保留。')) {
                invoke('quit_app_cmd');
              }
            }}
            disabled={!!busy}
            title="彻底退出（托盘图标也会消失）"
          >
            <Power />
            退出
          </button>
        </div>
      </section>

      {(error || toast) && (
        <div className={error ? 'notice error' : 'notice'}>
          {error ? <ShieldAlert /> : <CheckCircle2 />}
          <span>{error || toast}</span>
          <button onClick={() => (error ? setError(null) : setToast(null))}>关闭</button>
        </div>
      )}

      {actionWarnings.length > 0 && (
        <div className="notice error">
          <ShieldAlert />
          <div className="warnings" style={{ marginTop: 0 }}>
            {actionWarnings.map((warning, i) => (
              <div key={`${i}-${warning}`}>
                <ShieldAlert />
                {warning}
              </div>
            ))}
          </div>
          <button onClick={() => setActionWarnings([])}>关闭</button>
        </div>
      )}

      {newAccountModalOpen && (
        <div className="modal-scrim" role="presentation">
          <section className="prepare-modal" role="dialog" aria-modal="true" aria-labelledby="prepare-title">
            <div className="modal-title" id="prepare-title">
              <ShieldAlert />
              <div>
                <strong>准备尼区新号登录</strong>
                <span>保存当前账号、切换 Auto-Claude、清理 OAuth；不会自动打开浏览器或 Claude。</span>
              </div>
            </div>

            <div className="prepare-summary">
              <div>
                <span>新号</span>
                <strong>{newAccountName || '未命名'}</strong>
              </div>
              <div>
                <span>节点</span>
                <strong>{newAccountNode || '未选择'}</strong>
              </div>
              <div>
                <span>环境</span>
                <strong>
                  {newAccountTimezone || '未设置'} · {newAccountChromeProfile || '未设置'}
                </strong>
              </div>
            </div>

            <label className="work-note">
              当前正在干的事
              <textarea
                value={currentWorkNote}
                onChange={(event) => setCurrentWorkNote(event.target.value)}
                disabled={newAccountModalState !== 'draft'}
                rows={4}
                placeholder="例如：BuildYou 5050 hook 清理，下一步验证 hiddenSelectedImageDefaults 是否能原生化"
              />
            </label>

            <div className="prepare-progress">
              <div className="progress-label">
                <span>{newAccountStep}</span>
                <strong>{newAccountProgress}%</strong>
              </div>
              <div className="progress-track">
                <div className="progress-fill" style={{ width: `${newAccountProgress}%` }} />
              </div>
            </div>

            <div className="modal-actions">
              <button className="ghost" onClick={closePrepareNewAccountModal} disabled={newAccountModalState === 'running'}>
                {newAccountModalState === 'done' ? '关闭' : '取消'}
              </button>
              {newAccountModalState === 'done' ? (
                <button className="primary" onClick={closePrepareNewAccountModal}>
                  已准备好，我手动授权
                </button>
              ) : (
                <button className="primary" onClick={prepareNewAccount} disabled={newAccountModalState === 'running'}>
                  {newAccountModalState === 'running' ? <Loader2 className="spin" /> : <ShieldAlert />}
                  开始准备环境
                </button>
              )}
            </div>
          </section>
        </div>
      )}

      <section className="grid">
        <div className="panel current-panel">
          <div className="panel-title">
            <UserRound />
            <span>当前本机状态</span>
          </div>
          <div className="identity">
            <strong>{statusAccountLabel(status)}</strong>
            <span>{statusOrganizationLabel(status)}</span>
          </div>
          <div className="pills">
            <StatusPill ok={!!status?.claude_json_exists} label="~/.claude.json" />
            <StatusPill ok={!!status?.keychain_exists} label={credentialLabel} />
            <StatusPill ok={!!status?.keychain_parse_ok} label="凭据 JSON" />
            <StatusPill ok={!!status?.settings_json_exists} label="settings.json" />
          </div>
          <div className="fields two">
            <Field label="账号 UUID" value={shortId(status?.meta.account_uuid)} />
            <Field label="组织 UUID" value={shortId(status?.meta.organization_uuid)} />
            <Field label="Device ID 哈希" value={status?.meta.user_id_hash} />
            <Field label="订阅" value={status?.meta.subscription_type} />
            <Field label="限额层级" value={status?.meta.rate_limit_tier} />
          </div>
          {!!status?.warnings.length && (
            <div className="warnings">
              {status.warnings.map((warning, i) => (
                <div key={`${i}-${warning}`}>
                  <ShieldAlert />
                  {warning}
                </div>
              ))}
            </div>
          )}
          <div className="status-icons">
            <StatusIcon
              ok={!!status?.meta.has_oauth_account}
              label="账号"
              detail={statusAccountLabel(status)}
            />
            <StatusIcon
              ok={!!status?.keychain_exists && !!status?.keychain_parse_ok}
              label={credentialLabel}
              detail={status?.keychain_exists ? 'OAuth 已保存' : '未发现'}
            />
            <StatusIcon
              ok={!!clashStatus?.available}
              label="Auto-Claude"
              detail={clashStatus?.now || '未连接'}
            />
            <StatusIcon
              ok={typeof usage?.session.used_percent === 'number' || !!usage?.scanned_messages}
              label="额度"
              detail={usage ? usageLabel(usage.session) : '读取中'}
            />
          </div>
        </div>

        <div className="panel capture-panel">
          <div className="panel-title">
            <Plus />
            <span>保存当前账号</span>
          </div>
          <label>
            名称
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="例如 Claude 主号 / Claude 备用号"
            />
          </label>
          <label>
            备注
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="用途、套餐、来源，留空也可以"
              rows={4}
            />
          </label>
          <button className="primary" onClick={capture} disabled={!canCapture}>
            {busy === 'capture' ? <Loader2 className="spin" /> : <FileKey />}
            保存快照
          </button>
        </div>

        <div className="panel onboarding-panel">
          <div className="panel-title">
            <UserRound />
            <span>一键新号</span>
          </div>
          {status?.pending_new_account ? (
            <div className="pending-account">
              <div>
                <span>待完成</span>
                <strong>{status.pending_new_account.name}</strong>
              </div>
              <div>
                <span>节点</span>
                <strong>{status.pending_new_account.node}</strong>
              </div>
              <div>
                <span>环境</span>
                <strong>
                  {status.pending_new_account.runtime.timezone || '未设置'} ·{' '}
                  {status.pending_new_account.runtime.locale || '未设置'}
                </strong>
              </div>
              <div>
                <span>Chrome</span>
                <strong>{status.pending_new_account.runtime.chrome_profile || '未绑定'}</strong>
              </div>
              <p>环境已准备好。确认 IP / Chrome Profile 都正确后，手动打开 Claude Code 授权；完成 OAuth 后点下面保存成正式账号。</p>
              <button className="primary wide" onClick={finishNewAccount} disabled={!canFinishNewAccount}>
                {busy === 'finish-new' ? <Loader2 className="spin" /> : <CheckCircle2 />}
                登录完成后保存
              </button>
              <button className="ghost wide" onClick={cancelNewAccount} disabled={!!busy}>
                {busy === 'switch' ? <Loader2 className="spin" /> : <RotateCcw />}
                取消这次准备并切回当前账号
              </button>
            </div>
          ) : (
            <>
              <label>
                新号名称
                <input
                  value={newAccountName}
                  onChange={(event) => setNewAccountName(event.target.value)}
                  placeholder="例如 尼区 / Claude 备用号"
                />
              </label>
              <label>
                绑定节点
                <select
                  value={newAccountNode}
                  onChange={(event) => setNewAccountNode(event.target.value)}
                  disabled={!!busy || !clashStatus?.nodes.length}
                >
                  <option value="">选择新号节点</option>
                  {clashStatus?.nodes.map((node) => (
                    <option key={node} value={node}>
                      {node}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                备注
                <textarea
                  value={newAccountNotes}
                  onChange={(event) => setNewAccountNotes(event.target.value)}
                  placeholder="套餐、地区、用途，留空也可以"
                  rows={3}
                />
              </label>
              <div className="runtime-grid">
                <label>
                  时区
                  <input
                    value={newAccountTimezone}
                    onChange={(event) => setNewAccountTimezone(event.target.value)}
                    placeholder="Africa/Lagos"
                  />
                </label>
                <label>
                  语言
                  <input
                    value={newAccountLocale}
                    onChange={(event) => setNewAccountLocale(event.target.value)}
                    placeholder="en_US.UTF-8"
                  />
                </label>
                <label>
                  Chrome Profile
                  <input
                    value={newAccountChromeProfile}
                    onChange={(event) => setNewAccountChromeProfile(event.target.value)}
                    placeholder="Profile 4"
                  />
                </label>
              </div>
              <button className="primary wide" onClick={openPrepareNewAccountModal} disabled={!canPrepareNewAccount}>
                {busy === 'new-login' ? <Loader2 className="spin" /> : <ShieldAlert />}
                准备环境，不打开登录
              </button>
            </>
          )}
        </div>

        <div className="panel network-panel">
          <div className="panel-title">
            <Network />
            <span>网络节点</span>
          </div>
          <div className="clash-summary">
            <div>
              <span>控制器</span>
              <strong>{clashStatus?.controller || '未连接'}</strong>
            </div>
            <div>
              <span>组</span>
              <strong>{clashStatus?.group || 'Auto-Claude'}</strong>
            </div>
            <div>
              <span>当前节点</span>
              <strong>{clashStatus?.now || '未读取'}</strong>
            </div>
            <div>
              <span>组类型</span>
              <strong>{clashStatus?.group_type || '未知'}</strong>
            </div>
          </div>
          {clashStatus?.error && <div className="inline-error">{clashStatus.error}</div>}
          {clashStatus?.group_type && clashStatus.group_type !== 'Selector' && (
            <div className="inline-warning">Auto-Claude 不是 select 组，固定账号节点可能被自动测速覆盖。</div>
          )}
          <button className="ghost wide" onClick={() => load()} disabled={!!busy}>
            <RefreshCw />
            刷新 Clash 状态
          </button>
        </div>

        <div className="panel usage-panel">
          <div className="panel-title">
            <BarChart3 />
            <span>Claude 用量</span>
          </div>
          <div className="usage-hero">
            <div>
              <span>更新于 {relativeTime(usage?.updated_at)}</span>
              <strong>{usage ? usageLabel(usage.session) : '读取中'}</strong>
            </div>
            <button className="usage-refresh" onClick={refreshUsage} disabled={usageRefreshing} title="刷新 Claude 用量">
              {usageRefreshing ? <Loader2 className="spin" /> : <RefreshCw />}
            </button>
          </div>
          <div className="usage-grid">
            <UsageRow item={usage?.session ?? fallbackWindow('近 5 小时')} max={usageMax} />
            <UsageRow item={usage?.weekly ?? fallbackWindow('近 7 天')} max={usageMax} />
          </div>
          <div className="usage-stats">
            <div>
              <span>今天</span>
              <strong>{compactNumber(usage?.today.totals.total_tokens)}</strong>
            </div>
            <div>
              <span>近 30 天</span>
              <strong>{compactNumber(usage?.last_30_days.totals.total_tokens)}</strong>
            </div>
            <div>
              <span>常用模型</span>
              <strong>{usage?.top_model || '暂无'}</strong>
            </div>
            <div>
              <span>日志</span>
              <strong>{usage?.scanned_files ?? 0} 文件</strong>
            </div>
          </div>
          <div className="daily-bars" aria-label="近 30 天 token 用量">
            {(usage?.daily ?? []).map((item) => (
              <span
                key={item.date}
                title={`${item.date} · ${compactNumber(item.totals.total_tokens)} token`}
                style={{
                  height: `${Math.max(4, (item.totals.total_tokens / dailyMax) * 76)}px`,
                }}
              />
            ))}
          </div>
          <p className="usage-note">
            额度百分比来自官方 Claude OAuth API；token 和柱状图来自本地日志，用于判断消耗趋势。
          </p>
          {!!usage?.warnings.length && (
            <div className="warnings compact">
              {usage.warnings.map((warning, i) => (
                <div key={`${i}-${warning}`}>
                  <Activity />
                  {warning}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel files-panel">
          <div className="panel-title">
            <Database />
            <span>数据位置</span>
          </div>
          <div className="path-list">
            <code>{status?.claude_json_path}</code>
            <code>{status?.settings_json_path}</code>
            <code>{status?.data_dir}</code>
          </div>
          <div className="link-mode-row">
            <span>session 隔离链接</span>
            <strong>{status?.session_isolation.link_mode ?? '读取中'}</strong>
          </div>
          {platform === 'windows' && status?.session_isolation.degraded && (
            <div className="inline-warning">
              <div>
                Windows 未开启「开发者模式」时目录/文件链接会降级为 Junction / 硬链接：硬链接模式下
                Claude Code 若用「写临时文件再改名」更新 config.json，隔离可能被悄悄解除。
                建议打开开发者模式后，重新点一次「切换」以恢复符号链接。
              </div>
              <button
                className="ghost wide"
                onClick={() =>
                  run(null, async () => {
                    await invoke('open_developer_settings');
                  })
                }
                disabled={!!busy}
              >
                打开 Windows 开发者设置
              </button>
            </div>
          )}
          <button className="ghost wide" onClick={openDataDir} disabled={!!busy}>
            <ExternalLink />
            打开本工具数据目录
          </button>
          <div className="link-mode-row">
            <span>Claude 配置目录（当前生效）</span>
            <code title="凭据、settings.json、projects 都在这个目录下">{claudeConfigDir}</code>
          </div>
          {claudeConfigOverride && (
            <div className="link-mode-row">
              <span>已指定覆盖</span>
              <code>{claudeConfigOverride}</code>
            </div>
          )}
          <label className="work-note">
            指定 Claude 配置目录（留空保存 = 清除覆盖，跟随 CLAUDE_CONFIG_DIR / 默认 ~/.claude）
            <div className="node-bind">
              <input
                value={claudeConfigOverride}
                onChange={(event) => setClaudeConfigOverride(event.target.value)}
                placeholder="例如 D:\claude-alt（留空恢复默认）"
                disabled={!!busy}
              />
              <button
                className="ghost"
                onClick={() =>
                  run('bind', async () => {
                    const message = await invoke<string>('set_claude_config_dir', {
                      path: claudeConfigOverride,
                    });
                    const [next, override] = await Promise.all([
                      invoke<string>('get_claude_config_dir'),
                      invoke<Option<string>>('get_claude_config_dir_override'),
                    ]);
                    setClaudeConfigDir(next);
                    setClaudeConfigOverride(override ?? '');
                    return message;
                  })
                }
                disabled={!!busy}
              >
                保存
              </button>
            </div>
          </label>
          <button
            className="ghost wide"
            onClick={() =>
              run(null, async () => {
                const dir = await invoke<string>('get_logs_dir');
                await invoke('open_logs_dir');
                return `日志目录：${dir}`;
              })
            }
            disabled={!!busy || platform !== 'windows'}
            title="发布版不显示控制台，排错请查看日志文件"
          >
            <FileText />
            打开日志目录
          </button>
          <label className="link-mode-row" style={{ cursor: 'pointer' }}>
            <span>诊断时包含网络检查（Clash / OAuth）</span>
            <input
              type="checkbox"
              checked={includeNetwork}
              onChange={(event) => setIncludeNetwork(event.target.checked)}
              disabled={!!busy}
              style={{ width: 16, height: 16, flex: '0 0 auto' }}
            />
          </label>
          <button
            className="ghost wide"
            onClick={copyDiagnostics}
            disabled={!!busy}
            title="把诊断信息复制到剪贴板（排障时发给维护者）"
          >
            <ClipboardCopy />
            复制诊断信息
          </button>
          {platform === 'windows' && (
            <button
              className="ghost wide"
              onClick={() =>
                run('autostart', async () => {
                  const next = !autostart;
                  try {
                    await invoke('set_autostart', { enabled: next });
                  } catch (err) {
                    // 后端失败时不改 UI 状态，避免显示与实际注册表不一致。
                    throw err;
                  }
                  setAutostart(next);
                  return next ? '已开启开机自启' : '已关闭开机自启';
                })
              }
              disabled={!!busy || platform !== 'windows'}
              title="写入 HKCU\...\Run 注册表项，仅对当前用户生效"
            >
              <Power />
              {autostart ? '关闭开机自启' : '开启开机自启'}
            </button>
            {autostartDisabled && (
              <div className="inline-warning">
                启动项已在 Windows 任务管理器（「启动应用」）中被禁用，本工具无法代为恢复。
                请打开 任务管理器 → 启动应用，把 Claude Switcher 设为「已启用」。
              </div>
            )}
          )}
        </div>
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>账号快照</h2>
          <span>{profiles.length} 个</span>
        </div>
        {profiles.length === 0 ? (
          <div className="empty">
            <Fingerprint />
            <strong>还没有保存账号快照</strong>
            <span>先登录一个 Claude Code 账号，然后在上方保存当前账号。</span>
          </div>
        ) : (
          <div className="profile-grid">
            {profiles.map((profile) => (
              <article className={profile.is_current ? 'profile active' : 'profile'} key={profile.id}>
                <div className="profile-head">
                  <div>
                    <strong>{profile.name}</strong>
                    <span>{shortId(profile.meta.email)}</span>
                  </div>
                  {profile.is_current && <span className="active-mark">当前</span>}
                </div>
                <div className="mini-fields">
                  <span>
                    <Fingerprint />
                    Device {profile.meta.user_id_hash || '无'}
                  </span>
                  <span>
                    <Clock />
                    {dateLabel(profile.last_switched_at)}
                  </span>
                  <span>
                    <Router />
                    {profile.clash?.enabled ? profile.clash.node : '节点未绑定'}
                  </span>
                </div>
                <div className="node-bind">
                  <select
                    value={profile.clash?.enabled ? profile.clash.node : ''}
                    onChange={(event) => bindNode(profile.id, event.target.value)}
                    disabled={!!busy || !clashStatus?.nodes.length}
                  >
                    <option value="">不自动切节点</option>
                    {clashStatus?.nodes.map((node) => (
                      <option key={node} value={node}>
                        {node}
                      </option>
                    ))}
                  </select>
                  <button
                    className="ghost"
                    onClick={() => testProfileNode(profile.id)}
                    disabled={!!busy || !profile.clash?.enabled}
                  >
                    测节点
                  </button>
                </div>
                <div className="runtime-bind">
                  <input
                    defaultValue={profile.runtime?.timezone ?? ''}
                    onBlur={(event) => bindRuntime(profile, { timezone: event.target.value })}
                    disabled={!!busy}
                    placeholder="TZ: America/Los_Angeles"
                  />
                  <input
                    defaultValue={profile.runtime?.locale ?? ''}
                    onBlur={(event) => bindRuntime(profile, { locale: event.target.value })}
                    disabled={!!busy}
                    placeholder="Locale: en_US.UTF-8"
                  />
                  <input
                    defaultValue={profile.runtime?.chrome_profile ?? ''}
                    onBlur={(event) => bindRuntime(profile, { chrome_profile: event.target.value })}
                    disabled={!!busy}
                    placeholder="Chrome: Profile 35"
                  />
                </div>
                {profile.notes && <p>{profile.notes}</p>}
                <div className="profile-actions">
                  <button
                    className="primary"
                    onClick={() => switchTo(profile.id)}
                    disabled={!!busy}
                  >
                    {busy === 'switch' ? <Loader2 className="spin" /> : <CheckCircle2 />}
                    {currentProfile?.id === profile.id ? '重新应用' : '切换'}
                  </button>
                  <button className="danger" onClick={() => remove(profile.id, profile.name)} disabled={!!busy}>
                    <Trash2 />
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>遥测去关联</h2>
          <span>
            {TELEMETRY_OPTIONS.find((o) => o.value === telemetryMode)?.label ?? '读取中'}
          </span>
        </div>
        <div className="panel telemetry-panel">
          <div className="panel-title">
            <EyeOff />
            <span>隐私环境变量注入</span>
          </div>
          <p className="telemetry-intro">
            统一写入 ~/.claude/settings.json 的 env；三档隐私 env 互斥，切换时只动这两个 key，不影响 settings 里其它字段。
          </p>
          <div className="telemetry-options">
            {TELEMETRY_OPTIONS.map((option) => {
              const selected = telemetryMode === option.value;
              return (
                <button
                  key={option.value}
                  className={selected ? 'primary' : 'ghost'}
                  onClick={() => applyTelemetryMode(option.value)}
                  disabled={!!busy || telemetryMode === null}
                >
                  {busy === 'telemetry' && selected ? (
                    <Loader2 className="spin" />
                  ) : selected ? (
                    <CheckCircle2 />
                  ) : null}
                  {option.label}
                  {option.badge && <span className="telemetry-badge">{option.badge}</span>}
                </button>
              );
            })}
          </div>
          <div className="telemetry-desc">
            {TELEMETRY_OPTIONS.map((option) => (
              <p
                key={option.value}
                className={telemetryMode === option.value ? 'active' : ''}
              >
                <strong>{option.label}</strong>
                {option.desc}
              </p>
            ))}
          </div>
          {telemetryMode === 'essentialOnly' && (
            <div className="inline-error">
              最强档还会关掉 auto-update / 新模型能力拉取 / trusted-device（手机 bridge）注册——需手动更新 Claude Code。
            </div>
          )}
        </div>
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>备份与恢复</h2>
          <button className="ghost" onClick={refreshBackups} disabled={!!busy}>
            {busy === 'list-backups' ? <Loader2 className="spin" /> : <History />}
            刷新备份列表
          </button>
        </div>
        {backups.length === 0 ? (
          <div className="empty">
            <History />
            <strong>还没有备份</strong>
            <span>切换账号或点击「手动备份」后会在这里出现。</span>
          </div>
        ) : (
          <div className="profile-grid">
            {backups.map((item) => (
              <article className="profile" key={item.id}>
                <div className="profile-head">
                  <div>
                    <strong>{item.label}</strong>
                    <span>{dateLabel(item.created_at)}</span>
                  </div>
                </div>
                <div className="mini-fields">
                  <span>
                    <Clock />
                    {dateLabel(item.created_at)}
                  </span>
                  <span>
                    <FileKey />
                    {item.id}
                  </span>
                </div>
                <div className="profile-actions">
                  <button
                    className="primary"
                    onClick={() => restore(item.id, item.label)}
                    disabled={!!busy}
                  >
                    {busy === 'restore' ? <Loader2 className="spin" /> : <RotateCcw />}
                    恢复
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

export default App;
