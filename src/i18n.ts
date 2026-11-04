// 产品界面固定使用简体中文；系统语言与旧版语言选择不影响显示。
// 保留原语言接口，避免旧调用方传入英文选项时恢复英文界面。
export type Lang = 'zh' | 'en';
type Dict = Record<string, string>;

const zh: Dict = {
  'common.busy': '处理中…',
  'common.error': '错误',
  'common.language': '语言',
  'integ.title': '命令行集成与工具',
  'integ.path.title': '用户 PATH（命令行）',
  'integ.path.intro':
    '把工具可执行文件目录加入用户 PATH，即可在任意位置使用 cs 命令。以 REG_EXPAND_SZ 写回，保留 %USERPROFILE% 等变量不被展开。',
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
    '生成脱敏压缩包（令牌与邮箱均已脱敏）。完整便携版随包固定 WebView2 运行时并设置 WEBVIEW2_BROWSER_EXECUTABLE_FOLDER。',
  'integ.diag.build': '生成诊断包',
  'token.valid': '有效',
  'token.expiring': '即将过期',
  'token.expired.refresh': '访问令牌已过期，使用时自动续期',
  'token.expired.noRefresh': '无刷新令牌，需重新登录',
  'token.unknown': '未知',
  'provider.title': '第三方供应商',
  'provider.intro':
    'Anthropic 兼容端点。只修改本功能管理的环境变量；切回 OAuth 账号时清除这些变量。ANTHROPIC_AUTH_TOKEN 优先级高于已保存的 OAuth。',
  'provider.name': '名称',
  'provider.baseUrl': '服务地址',
  'provider.authToken': '认证令牌（加密保存）',
  'provider.modelEnv': '模型环境变量（每行 KEY=VALUE）',
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
  // 工作区资产管理
  'ws.title': '工作区资产',
  'ws.panel.title': '技能 / 命令 / 子代理 / CLAUDE.md（启用/停用）',
  'ws.search': '搜索名称或说明',
  'ws.skill': '技能',
  'ws.command': '命令',
  'ws.agent': '子代理',
  'ws.memory': '项目记忆 CLAUDE.md',
  'ws.enable': '启用',
  'ws.disable': '停用',
  'ws.empty': '没有匹配的工作区资产。',
  'ws.count': '{n} 项 · {enabled} 启用',
  // 权限与钩子编辑器
  'perm.title': '权限与钩子',
  'perm.panel.title': '权限规则与钩子编辑器',
  'perm.allow': '允许',
  'perm.deny': '拒绝',
  'perm.ask': '询问',
  'perm.allow.hint': '始终放行的工具/规则',
  'perm.deny.hint': '始终禁止',
  'perm.ask.hint': '每次先询问',
  'perm.rule.placeholder': '例如 Bash(npm run build)',
  'perm.hooks': '钩子（{n}）',
  'perm.hooks.note':
    '此列表是权威的：在这里删掉的钩子保存时会被真正删除。读不出命令行的钩子、以及超时设置等本编辑器不认识的字段会原样保留，不会被改动。',
  'perm.noHooks': '暂无钩子。',
  'perm.event': '事件（例如 Stop）',
  'perm.matcher': '匹配器（可空）',
  'perm.command': '命令行',
  'perm.addHook': '添加钩子',
  'perm.save': '保存',
  'perm.saved': '已保存到 settings.json。',
  'perm.perLine': '每行一条',
};

/** 初始化文档语言，供辅助技术与日期格式识别。 */
export async function initI18n() {
  document.documentElement.lang = 'zh-CN';
}

export function getLang(): Lang {
  return 'zh';
}

export function setLang(_lang: Lang) {
  document.documentElement.lang = 'zh-CN';
}

/** 翻译与参数替换；缺失文案也不会回退英文。 */
export function t(key: string, params?: Record<string, string | number>): string {
  let text = zh[key] ?? '暂无中文说明';
  if (params) {
    for (const [name, value] of Object.entries(params)) {
      text = text.replace(`{${name}}`, String(value));
    }
  }
  return text;
}

export function useI18n() {
  return { t, lang: getLang(), setLang };
}
