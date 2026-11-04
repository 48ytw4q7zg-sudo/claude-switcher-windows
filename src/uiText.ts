/** 产品控制的技术状态只在显示时翻译，后端字段和用户数据保持原样。 */
const technicalLabels: Record<string, string> = {
  Selector: '手动选择',
  URLTest: '自动测速',
  Fallback: '故障转移',
  LoadBalance: '负载均衡',
  Direct: '直连',
  Reject: '拒绝连接',
  Junction: '目录联接',
  'native(官方安装脚本)': '原生安装（官方安装脚本）',
  'unknown(建议核对 PATH)': '未知（建议核对 PATH）',
  unknown: '未知',
  rule: '规则模式',
  global: '全局模式',
  direct: '直连模式',
  npm: 'npm 安装',
  bun: 'bun 安装',
};

export function technicalLabel(value?: string | null, fallback = '未知'): string {
  if (!value) return fallback;
  return technicalLabels[value] ?? value;
}

/** 用中文数量单位展示词元数，数值本身不变。 */
export function compactNumber(value?: number | null): string {
  const next = value ?? 0;
  if (next >= 100_000_000) return `${(next / 100_000_000).toFixed(next >= 1_000_000_000 ? 0 : 1)}亿`;
  if (next >= 10_000) return `${(next / 10_000).toFixed(next >= 100_000 ? 0 : 1)}万`;
  return next.toLocaleString('zh-CN');
}

const ERROR_MESSAGES: [RegExp, string][] = [
  [/timed?\s*out|timeout|超时/i, '操作超时，请检查连接或稍后重试。'],
  [/permission denied|access is denied|access denied|拒绝访问|权限不足/i, '访问被拒绝，请检查文件权限或系统授权。'],
  [/used by another process|sharing violation|被另一个进程使用|文件被占用/i, '文件正在被其他程序使用，请关闭相关程序后重试。'],
  [/no such file|file not found|cannot find the (?:file|path)|找不到指定的(?:文件|路径)/i, '未找到所需文件或目录，请检查路径。'],
  [/connection refused|actively refused|连接被拒绝/i, '连接被拒绝，请检查目标服务和代理是否运行。'],
  [/dns|name resolution|failed to lookup address/i, '无法解析服务器地址，请检查网络和代理设置。'],
  [/certificate|tls|ssl|证书/i, '安全连接验证失败，请检查系统时间、证书和代理设置。'],
  [/unauthorized|unauthenticated|authentication failed/i, '身份验证失败，请检查登录状态或认证信息。'],
  [/forbidden/i, '服务拒绝访问，请检查账号权限和服务配置。'],
  [/too many requests|rate limit/i, '请求过于频繁或已达额度限制，请稍后重试。'],
  [/failed to fetch|network error|error sending request|connection reset|transport failed/i, '网络请求失败，请检查网络、代理和服务状态。'],
  [/invalid (?:type|value)|expected .* at line|json parse|unexpected (?:token|end)/i, '配置数据无法解析，请检查文件格式和字段内容。'],
  [/invalid url|relative url|empty host/i, '服务地址格式无效，请检查协议、主机和端口。'],
  [/disk full|not enough space|磁盘空间不足/i, '磁盘空间不足，请释放空间后重试。'],
  [/internal server error|bad gateway|service unavailable/i, '服务暂时不可用，请稍后重试。'],
];

function canDisplayMessage(detail: string): boolean {
  // 账号名、路径、命令与品牌属于技术值，不按英文句子处理。
  const prose = detail
    .replace(/「[^」]*」|`[^`]*`/g, '')
    .replace(/(?:[A-Za-z]:[\\/]|https?:\/\/)[^\r\n，。；]+/g, '')
    .replace(/Claude Code|Claude Desktop|Windows Terminal|Microsoft Edge|Google Chrome/g, '');
  const containsEnglishSentence = /(?:\b[a-z]+[ \t]+){1,}[a-z]+\b/i.test(prose);
  const containsSecret = /(?:authorization|password|[a-z_]*token|api[_-]?key|secret)["']?\s*[=:]|\b(?:sk-ant-|Bearer\s)|https?:\/\/[^/\s]+:[^/\s]+@/i.test(detail);
  return /[\u3400-\u9fff]/.test(detail) && !containsEnglishSentence && !containsSecret;
}

/** 不记录或直接回显原始英文异常；未知异常只给中文提示和可识别的错误码。 */
export function formatError(error: unknown, fallback = '操作未完成，请检查当前设置后重试。'): string {
  const detail = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  // 中文业务提示可能说明部分操作成功或提供恢复路径，不能被通用错误覆盖。
  if (canDisplayMessage(detail)) return detail;
  const systemCode = detail.match(/os error\s+(\d+)/i)?.[1];
  const httpCode = detail.match(/\bHTTP(?:\s+status)?\s*[:=]?\s*([45]\d{2})\b/i)?.[1];
  const suffix = [systemCode && `系统错误 ${systemCode}`, httpCode && `HTTP 状态码 ${httpCode}`]
    .filter(Boolean).join('，');
  const translated = detail
    .replace(/\b(?:Error|TypeError|SyntaxError):\s*/g, '错误：')
    .replace(/\(os error (\d+)\)/gi, '（系统错误 $1）')
    .replace(/access is denied|access denied|permission denied/gi, '访问被拒绝')
    .replace(/no such file or directory|file not found/gi, '文件或目录不存在')
    .replace(/the (?:system )?cannot find the (?:file|path) specified/gi, '找不到指定的文件或路径')
    .replace(/the process cannot access the file because it is being used by another process/gi, '文件正在被其他程序使用')
    .replace(/connection refused/gi, '连接被拒绝')
    .replace(/(?:operation |request )?timed out|timeout/gi, '操作超时')
    .replace(/failed to fetch|network error|error sending request/gi, '网络请求失败');
  if (canDisplayMessage(translated)) return translated;
  const known = ERROR_MESSAGES.find(([pattern]) => pattern.test(detail));
  return `${known?.[1] ?? fallback}${suffix ? `（${suffix}）` : ''}`;
}

/** 状态和警告也可能夹带底层英文异常，统一通过中文展示边界。 */
export function formatMessage(value: string): string {
  return formatError(value, '状态说明暂时无法显示，请刷新后重试。');
}

export function backupLabel(value: string): string {
  if (value === 'manual') return '手动备份';
  if (value === 'before-new-account-login') return '新账号登录前备份';
  if (value === 'before-restore') return '恢复前备份';
  if (value.startsWith('before-switch-to-')) return `切换前备份（${value.slice('before-switch-to-'.length)}）`;
  return value;
}

const diagnosticKeys: Record<string, string> = {
  schema_version: '报告格式版本', mode: '诊断方式', scope: '检查范围',
  account_status: '账号状态', leak_protection: '防泄漏状态', launch_allowed: '是否允许启动',
  application_started: '是否已启动应用', system_modified: '是否已修改系统',
  note: '说明', state: '结果', error: '错误', hint: '建议', detail: '详细说明',
  proxy: '代理配置', scheme: '协议', port: '端口', host_scope: '地址范围',
  authentication_configured: '是否配置认证', source: '配置来源', checks: '检查项目',
  name: '项目名称', url: '目标地址', transport_reached: '传输是否到达',
  http_status: 'HTTP 状态码', access: '访问结果', elapsed_seconds: '耗时（秒）',
};

const diagnosticValues: Record<string, string> = {
  proxy_diagnostics: '代理诊断', unauthenticated_transport_only: '仅检查无认证传输',
  not_evaluated: '未评估', configuration_error: '配置错误',
  invalid_or_missing_proxy: '代理地址无效或未填写', proxy_client_build_failed: '代理连接初始化失败',
  transport_reached: '传输已到达', transport_failed: '传输失败',
  loopback: '本机回环地址', remote: '远程地址', argument: '本次输入',
  anthropic_api: 'Anthropic 接口', claude_web: 'Claude 网页',
  probe_timeout: '探测超时', connect_failed: '连接失败', unknown: '未知',
  accessible: '可访问', authentication_required: '需要认证', forbidden: '访问被拒绝',
  rate_limited: '请求受限', server_error: '服务错误', redirect: '重定向',
  unauthenticated: '尚未认证', access_restricted: '访问受限', http_response: '已收到响应',
};

/** 仅生成展示副本；不改变后端报告或用于导出的诊断数据。 */
export function localizedDiagnostics(value: unknown, field?: string): unknown {
  if (value === null || value === undefined) return field === 'error' ? '无' : '未评估';
  if (typeof value === 'boolean') return value ? '是' : '否';
  if (Array.isArray(value)) return value.map((item) => localizedDiagnostics(item));
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [
      diagnosticKeys[key] ?? `其他字段（${key}）`, localizedDiagnostics(item, key),
    ]));
  }
  if (typeof value === 'string') {
    if (diagnosticValues[value]) return diagnosticValues[value];
    if (field === 'error' || field === 'detail') return formatError(value);
    if (field === 'note' || field === 'hint') return formatMessage(value);
    return value;
  }
  return value;
}
