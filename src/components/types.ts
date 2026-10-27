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
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`;
}
