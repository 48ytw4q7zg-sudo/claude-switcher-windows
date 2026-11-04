// 后端新模块返回结构（Tauri 对 struct 字段默认保留 Rust snake_case 命名）。
// 这些类型与 src-tauri 中的结构体一一对应，只列前端需要渲染的字段。

export type CheckStatus = 'ok' | 'warn' | 'fail';

export interface CheckItem {
  id: number;
  key: string;
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface ChecksSummary {
  total: number;
  ok: number;
  warn: number;
  fail: number;
  passed: boolean;
}

export interface FixStep {
  name: string;
  status: CheckStatus;
  detail: string;
}

export interface FixReport {
  steps: FixStep[];
  summary: ChecksSummary;
  checks: CheckItem[];
}

export interface EgressInfo {
  ip: string;
  country: string;
  iana_tz: string;
  org?: string | null;
  source: string;
}

export interface RegionPlan {
  country: string;
  iana_tz: string;
  windows_tz: string;
  locale: string;
  geo_id: number;
}

export interface RegionLockReport {
  plan: RegionPlan;
  applied: boolean;
  current_geo?: number | null;
  message: string;
}

export interface GuardTick {
  tun_up: boolean;
  tun_detail: string;
  client_up: boolean;
  alive: boolean;
  killed: string[];
}

/** 全局环境/代理偏好（对应后端 appconfig.json）。 */
export interface AppConfig {
  country_target?: string | null;
  tz_target?: string | null;
  locale_target?: string | null;
  proxy_mode?: string | null;
  proxy_group?: string | null;
  webrtc_policy?: string | null;
  last_egress_ip?: string | null;
  /** P2-1：额度阈值提醒开关（默认关闭）。 */
  quota_reminder_enabled?: boolean;
  /** P2-1：提醒阈值（默认 90）。 */
  quota_reminder_threshold?: number;
  /** H-6：检测到未登记账号时是否自动收养（默认开启）。 */
  auto_adopt_enabled?: boolean;
  /** 出口门禁：被监控的出口链路目标表。 */
  egate_targets?: EgateTarget[];
  /** 出口门禁总开关（默认关闭）。 */
  egate_enabled?: boolean;
  /** 熔断防抖阈值（连续 N 次失败才熔断；0 表示关闭熔断）。 */
  egate_trip_threshold?: number;
  /** 检查间隔秒数。 */
  egate_interval_secs?: number;
  /** 是否启用接入路径检查。 */
  egate_enforce_access?: boolean;
  /** 被守护的桌面应用 id。 */
  egate_guarded_agents?: string[];
}

/** 出口门禁：一个被监控的出口链路。 */
export interface EgateTarget {
  id: string;
  name: string;
  anchor_url: string;
  anchor_kind: 'auto' | 'trace' | 'json_ip' | 'gemini_region' | 'reachability';
  expect_ips: string[];
  expect_regions: string[];
  enabled: boolean;
  timeout_secs: number;
}

/** 出口门禁：单个目标的一轮结果。 */
export interface EgateTargetReport {
  id: string;
  name: string;
  verdict: 'pass' | 'fail' | 'unverified' | 'disabled';
  reason: string;
  fail_streak: number;
  ip?: string | null;
  country?: string | null;
  latency_ms: number;
}

/** 出口门禁：一轮检查的完整结果。 */
export interface EgateReport {
  access: { path: string; note: string };
  overall: { verdict: 'pass' | 'fail' | 'unverified' | 'disabled'; note: string };
  targets: EgateTargetReport[];
  probed: boolean;
  skipped_reason?: string | null;
  /** 是否达到熔断阈值。 */
  should_trip: boolean;
  /** 是否到预警点。 */
  should_warn: boolean;
  trip_threshold: number;
}

/** 出口门禁：单个应用的隔离结果。 */
export interface QuarantineReport {
  agent: string;
  rules_added: number;
  rules_verified: number;
  killed: string[];
  verified: boolean;
  note: string;
}

/** 出口门禁：一次熔断的完整结果。 */
export interface TripReport {
  agents: QuarantineReport[];
  isolated: boolean;
  failures: string[];
  note: string;
}

/** 出口门禁：直连泄露观察结果。 */
export interface LeakConn {
  pid: number;
  agent: string;
  remote: string;
  port: number;
}

export interface LeakReport {
  applicable: boolean;
  mode: string;
  agent_conns: number;
  proxied: number;
  local: number;
  direct: LeakConn[];
  direct_total: number;
  note: string;
}

/** 出口门禁：断网现场。 */
export interface CutState {
  mode: string;
  firewall: boolean;
  nics: string[];
  since: number;
}

/** P1-3：并行终端启动结果。 */
export interface ParallelTerminalResult {
  profile_id: string;
  config_dir: string;
  launcher: 'wt' | 'cmd-start' | string;
}

/** P2-1：推荐切换的账号。 */
export interface RecommendedAccount {
  id: string;
  name: string;
  last_used_percent?: number | null;
  /** H-2：推荐依据的缓存数据距今多少分钟。 */
  minutes_ago?: number | null;
}

/** P2-1：阈值提醒结果。 */
export interface QuotaReminder {
  enabled: boolean;
  threshold: number;
  current_percent?: number | null;
  recommended?: RecommendedAccount | null;
}

/** P2-3：MCP 服务器（stdio / http / sse）。 */
export interface McpServer {
  type?: 'stdio' | 'http' | 'sse' | string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export interface RulesReport {
  mode: string;
  script_changed: boolean;
  script_backup?: string | null;
  merge_changed: boolean;
  merge_backup?: string | null;
  kernel_verified: boolean;
  restart_attempted: boolean;
  messages: string[];
}

export interface DesktopProfile {
  id: string;
  name: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  last_switched_at?: string | null;
  snapshot_rel: string;
  size_bytes: number;
  meta?: Record<string, unknown> | null;
}

export interface SystemFingerprint {
  os_name?: string;
  os_version?: string;
  kernel_version?: string;
  host_name?: string;
  cpu_brand?: string;
  cpu_vendor?: string;
  cpu_frequency_mhz?: number;
  physical_cores?: number;
  total_memory_bytes: number;
  cpu_arch: string;
  virtual_machine: boolean;
  vm_reasons: string[];
  gpu: string;
  web_notice: string;
}

export interface CliInstance {
  path: string;
  order: number;
  version?: string;
  install_method: string;
}

export interface CliInfo {
  found: boolean;
  instances: CliInstance[];
  warnings: string[];
  config_dir?: string;
}

/** 把字节数格式化成可读字符串。 */
export function humanBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return '0 字节';
  const units = ['字节', '千字节', '兆字节', '吉字节'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}

/** 出口门禁：环境一致性检查结果。 */
export interface EnvCheck {
  tz_key: string;
  egress_country: string;
  expected_tz: string;
  tz_match: boolean;
  mismatched: boolean;
  note: string;
}
