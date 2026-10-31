// F-7 多语言：极简 i18n 框架。
// - 默认跟随系统：初始化时调用后端 get_system_language（GetUserDefaultUILanguage）。
// - 词典覆盖本轮新增面板；旧界面硬编码中文按增量迁移（见 docs/qa-v0.5.0.md）。
// - t() 支持 {name} 形式的参数替换；缺失键回退英文再回退键名。

import { invoke } from '@tauri-apps/api/core';
import { useEffect, useState } from 'react';

export type Lang = 'zh' | 'en';

type Dict = Record<string, string>;

const en: Dict = {
  // 通用
  'common.busy': 'Working…',
  'common.error': 'Error',
  'common.language': 'Language',
  // 集成面板
  'integ.title': 'CLI Integration & Tools',
  'integ.path.title': 'User PATH (command line)',
  'integ.path.intro':
    'Add the tool bin directory to your user PATH so the cs command works anywhere. Written as REG_EXPAND_SZ, variables like %USERPROFILE% are preserved.',
  'integ.path.add': 'Add to user PATH',
  'integ.path.remove': 'Remove from user PATH',
  'integ.bind.title': 'Directory binding (cs run)',
  'integ.bind.intro':
    'Bind a directory to an account. Running cs run in that folder (or a subfolder) starts Claude with that account via CLAUDE_CONFIG_DIR.',
  'integ.bind.dir': 'Directory path',
  'integ.bind.account': 'Account name',
  'integ.bind.bind': 'Bind directory',
  'integ.bind.unbind': 'Unbind directory',
  'integ.menu.title': 'Start menu shortcuts',
  'integ.menu.intro':
    'Create one Start menu shortcut per account (--switch-id <id>). Shortcuts are rebuilt to stay in sync after rename/delete.',
  'integ.menu.rebuild': 'Rebuild shortcuts',
  'integ.menu.clear': 'Clear all shortcuts',
  'integ.diag.title': 'Diagnostic bundle',
  'integ.diag.intro':
    'Build a sanitized zip (tokens and emails are redacted). The full portable edition bundles a fixed WebView2 runtime and sets WEBVIEW2_BROWSER_EXECUTABLE_FOLDER.',
  'integ.diag.build': 'Build diagnostic bundle',
  // 令牌状态
  'token.valid': 'Valid',
  'token.expiring': 'Expiring soon',
  'token.expired.refresh': 'Access token expired; it auto-refreshes when used',
  'token.expired.noRefresh': 'No refresh token; you need to sign in again',
  'token.unknown': 'Unknown',
  // 供应商
  'provider.title': 'Third-party providers',
  'provider.intro':
    'Anthropic-compatible endpoints. Only keys managed by this feature are changed; switch back to OAuth to clear them. ANTHROPIC_AUTH_TOKEN takes priority over the saved OAuth.',
  'provider.name': 'Name',
  'provider.baseUrl': 'Base URL',
  'provider.authToken': 'Auth token (encrypted)',
  'provider.modelEnv': 'Model env (KEY=VALUE, one per line)',
  'provider.create': 'Create provider',
  'provider.switch': 'Use this provider',
  'provider.test': 'Test connection',
  'provider.delete': 'Delete',
  'provider.active': 'Active',
  // WSL
  'wsl.title': 'WSL integration (experimental)',
  'wsl.intro':
    'Experimental and off by default. Credentials are written only when you explicitly choose a distro. The target 0600 permission cannot be guaranteed from Windows.',
  'wsl.enable': 'Enable WSL integration',
  'wsl.distro': 'Target distro',
  'wsl.refresh': 'Refresh distro list',
  'wsl.write': 'Write credentials',
  'wsl.clear': 'Clear credentials',
};

const zh: Dict = {
  'common.busy': '处理中…',
  'common.error': '错误',
  'common.language': '语言',
  'integ.title': '命令行集成与工具',
  'integ.path.title': '用户 PATH（命令行）',
  'integ.path.intro':
    '把工具 bin 目录加入用户 PATH，即可在任意位置使用 cs 命令。以 REG_EXPAND_SZ 写回，保留 %USERPROFILE% 等变量不被展开。',
  'integ.path.add': '加入用户 PATH',
  'integ.path.remove': '从用户 PATH 移除',
  'integ.bind.title': '目录绑定（cs run）',
  'integ.bind.intro':
    '把目录绑定到账号；在该目录（或子目录）执行 cs run，会通过 CLAUDE_CONFIG_DIR 用该账号启动 Claude。',
  'integ.bind.dir': '目录路径',
  'integ.bind.account': '账号名称',
  'integ.bind.bind': '绑定目录',
  'integ.bind.unbind': '解绑目录',
  'integ.menu.title': '开始菜单快捷方式',
  'integ.menu.intro':
    '为每个账号生成一个开始菜单快捷方式（--switch-id <id>）；重命名/删除后重建以保持同步。',
  'integ.menu.rebuild': '重建快捷方式',
  'integ.menu.clear': '全部清理',
  'integ.diag.title': '诊断包',
  'integ.diag.intro':
    '生成脱敏 zip（令牌与邮箱均已脱敏）。完整便携版随包固定 WebView2 运行时并设置 WEBVIEW2_BROWSER_EXECUTABLE_FOLDER。',
  'integ.diag.build': '生成诊断包',
  'token.valid': '有效',
  'token.expiring': '即将过期',
  'token.expired.refresh': '访问令牌已过期，使用时自动续期',
  'token.expired.noRefresh': '无刷新令牌，需重新登录',
  'token.unknown': '未知',
  'provider.title': '第三方供应商',
  'provider.intro':
    'Anthropic 兼容端点。只改本功能管理的 env 键；切回 OAuth 时清键。ANTHROPIC_AUTH_TOKEN 优先级高于已保存的 OAuth。',
  'provider.name': '名称',
  'provider.baseUrl': 'Base URL',
  'provider.authToken': 'Auth token（加密保存）',
  'provider.modelEnv': '模型 env（每行 KEY=VALUE）',
  'provider.create': '创建供应商',
  'provider.switch': '使用该供应商',
  'provider.test': '连通测试',
  'provider.delete': '删除',
  'provider.active': '当前生效',
  'wsl.title': 'WSL 集成（实验功能）',
  'wsl.intro':
    '实验功能，默认关闭。仅在你显式选择发行版时写入凭据。目标 0600 权限无法从 Windows 侧保证。',
  'wsl.enable': '启用 WSL 集成',
  'wsl.distro': '目标发行版',
  'wsl.refresh': '刷新发行版列表',
  'wsl.write': '写入凭据',
  'wsl.clear': '清除凭据',
};

let currentLang: Lang = 'zh';
const listeners = new Set<() => void>();

function emit() {
  listeners.forEach((fn) => fn());
}

/** 初始化：语言跟随系统（失败回退中文）。 */
export async function initI18n() {
  try {
    const code = await invoke<string>('get_system_language');
    currentLang = code.startsWith('zh') ? 'zh' : 'en';
  } catch {
    currentLang = 'zh';
  }
  emit();
}

export function getLang(): Lang {
  return currentLang;
}

export function setLang(lang: Lang) {
  currentLang = lang;
  emit();
}

/** 翻译 + 参数替换。 */
export function t(key: string, params?: Record<string, string | number>): string {
  const dict = currentLang === 'en' ? en : zh;
  let text = dict[key] ?? en[key] ?? key;
  if (params) {
    for (const [name, value] of Object.entries(params)) {
      text = text.replace(`{${name}}`, String(value));
    }
  }
  return text;
}

/** React 订阅：语言切换时重渲染。 */
export function useI18n() {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((x) => x + 1);
    listeners.add(fn);
    return () => {
      listeners.delete(fn);
    };
  }, []);
  return { t, lang: currentLang, setLang };
}
