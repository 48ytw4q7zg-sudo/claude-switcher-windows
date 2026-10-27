//! 隐私 / 诊断工具：open-safe、diagnose-proxy、fingerprint、cli-info。
//!
//! 行为基准（上游 core/claude-switch.sh 同名函数）：
//! - `open-safe <http(s)://url>`：一次性隔离浏览器窗口，独立临时 profile，禁用非代理
//!   UDP，关闭即销毁；代理未就绪时拒绝打开，以免直连泄露真实出口。
//! - `diagnose-proxy --proxy URL`：只验证**显式指定**代理到 claude.ai /
//!   api.anthropic.com 的**无认证**传输可达性，输出结构化 JSON；401/403 仅标注为
//!   「请求已到达服务器」，绝不等于账号可用。报告中不回显代理凭据/地址。
//! - `fingerprint`：系统侧硬件指纹（OS/CPU/内存/主机名）+ 虚拟机启发式；
//!   字体/GPU/Canvas/WebGL 由前端在 webview 内采集（后端拿不到，标 unknown，不编造）。
//! - `cli-info`：只读体检 PATH 中所有 claude 的位置/顺序/版本/安装方式，多份并存告警；
//!   不执行卸载/升级。
//!
//! 铁律：不写 `#[cfg(windows)]`（平台差异一律走 `crate::platform::imp`）；
//! 命令调用与输出解析分离（解析函数做表驱动单测）；阻塞操作由上层 Tauri command
//! 包 `blocking(...).await`（本文件只提供同步纯函数）。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use crate::paths;
use crate::platform::imp;

// ─────────────────────────────────────────────────────────────────────────────
// open-safe：一次性隔离浏览器
// ─────────────────────────────────────────────────────────────────────────────

/// 校验 URL 只允许 http/https。拒绝空串、file://、javascript:、data:、ftp: 等。
/// （对齐上游：`case "$url" in http://*|https://*) ;; *) 只允许 http/https ;; esac`）
fn validate_safe_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("用法: open-safe <http(s)://链接>".to_string());
    }
    let lower = url.to_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        Err("只允许 http/https 链接".to_string())
    }
}

/// TUN/虚拟网卡是否在线（用于 open-safe 的「代理就绪」门）。
///
/// 判定：存在 `Up` 状态、且名字/描述像 TUN（wintun/mihomo/tun/tap/wireguard/tailscale/
/// clash），或分配了 Clash fake-ip 段 `198.18.x.x` 的网卡。
/// 纯解析函数，输入网卡列表即输出 bool，可表驱动单测。
fn tun_ready(adapters: &[imp::AdapterInfo]) -> bool {
    adapters.iter().any(|a| {
        if a.status != "Up" {
            return false;
        }
        let blob = format!("{} {}", a.name, a.description).to_lowercase();
        let looks_virt = blob.contains("wintun")
            || blob.contains("mihomo")
            || blob.contains("tun")
            || blob.contains("tap")
            || blob.contains("wireguard")
            || blob.contains("tailscale")
            || blob.contains("clash");
        let fake_ip = a.ipv4.iter().any(|ip| ip.starts_with("198.18."));
        looks_virt || fake_ip
    })
}

/// open-safe 前置门：代理是否接管流量。未就绪则拒绝打开（防止浏览器直连）。
fn proxy_ready() -> Result<bool, String> {
    let adapters = imp::list_adapters()?;
    Ok(tun_ready(&adapters))
}

/// 定位本机 Chromium 内核浏览器（优先 Edge，回退 Chrome）。
fn find_browser() -> Result<String, String> {
    const CANDIDATES: [&str; 4] = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for candidate in CANDIDATES {
        if Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }
    Err("未找到 Edge/Chrome".to_string())
}

/// safe-profiles 根目录 `<app_data>/safe-profiles`（不存在则创建）。
fn safe_profiles_root() -> Result<PathBuf, String> {
    let root = paths::app_data_dir()?.join("safe-profiles");
    fs::create_dir_all(&root).map_err(|e| format!("创建 safe-profiles 目录失败: {e}"))?;
    Ok(root)
}

/// 构造隔离浏览器启动参数（纯函数，单测校验开关齐全）。
/// 对齐上游：--user-data-dir=<临时> --no-first-run --no-default-browser-check
/// --disable-sync --disable-extensions
/// --force-webrtc-ip-handling-policy=disable_non_proxied_udp --lang=en-US <url>
fn build_open_args(url: &str, profile: &Path) -> Vec<String> {
    vec![
        format!("--user-data-dir={}", profile.display()),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--disable-sync".to_string(),
        "--disable-extensions".to_string(),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
        "--lang=en-US".to_string(),
        "--new-window".to_string(),
        url.to_string(),
    ]
}

/// 打开一次性隔离浏览器。返回会话 id（用于 close_safe 销毁）。
pub fn open_safe(url: &str) -> Result<String, String> {
    validate_safe_url(url)?;
    if !proxy_ready()? {
        return Err(
            "代理未就绪（未检测到 TUN 接管），拒绝打开以免浏览器直连泄露真实出口".to_string(),
        );
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    let profile = safe_profiles_root()?.join(&id);
    fs::create_dir_all(&profile).map_err(|e| format!("创建临时 profile 失败: {e}"))?;
    let browser = find_browser()?;
    let args = build_open_args(url, &profile);
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    imp::start_detached(&browser, &args_ref).map_err(|e| format!("启动隔离浏览器失败: {e}"))?;
    Ok(id)
}

/// 结束指定会话的隔离浏览器进程并销毁临时目录。
///
/// 只杀「命令行引用了该 profile 目录」的浏览器进程（含 gpu/renderer 子进程），
/// 绝不按 exe 名全杀——那会误杀用户日常浏览器。
pub fn close_safe(id: &str) -> Result<(), String> {
    // id 只允许字母数字与连字符，防止路径穿越。
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("无效的会话 id".to_string());
    }
    let profile = safe_profiles_root()?.join(id);
    kill_browser_processes_for_profile(&profile);
    if !profile.exists() {
        return Ok(());
    }
    // 等进程真正退出再删目录（Windows 上被占用的目录删不掉），最多重试 ~2s。
    let _ = fs::remove_dir_all(&profile);
    for attempt in 0..5 {
        if !profile.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
        match fs::remove_dir_all(&profile) {
            Ok(()) => return Ok(()),
            Err(e) if attempt == 4 => {
                return Err(format!("销毁临时 profile 失败: {e}"));
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

/// 枚举进程，杀掉命令行含 `<profile>` 路径的浏览器进程（精确到本会话）。
fn kill_browser_processes_for_profile(profile: &Path) {
    let needle = profile.to_string_lossy().to_string();
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
    );
    let self_pid = imp::current_pid();
    for (pid, process) in system.processes() {
        if pid.as_u32() == self_pid {
            continue;
        }
        let hits = process
            .cmd()
            .iter()
            .any(|arg| arg.to_string_lossy().contains(needle.as_str()));
        if hits {
            process.kill();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// diagnose-proxy：显式代理的无认证传输可达性
// ─────────────────────────────────────────────────────────────────────────────

/// 校验后的代理 URL 的公开摘要（**不含凭据、不含完整地址**，可安全进报告）。
struct ValidatedProxy {
    scheme: String,
    port: u16,
    host_loopback: bool,
    auth: bool,
}

/// 校验代理 URL（对齐上游 Python `select_proxy`）：
/// scheme ∈ http/https/socks5/socks5h；必须有 host 与合法端口；
/// 不允许 path/query/fragment；不允许空白字符/控制字符。
/// 校验失败一律返回 Err，调用方降级为 configuration_error，不回显原始串。
fn validate_proxy_url(raw: &str) -> Result<ValidatedProxy, String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw
            .chars()
            .any(|c| c.is_whitespace() || (c as u32) < 32 || c == '\u{7f}')
    {
        return Err("invalid proxy".to_string());
    }
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or("invalid proxy: missing scheme")?;
    let scheme = scheme.to_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err("invalid proxy scheme".to_string());
    }
    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err("proxy URL must not contain path/query/fragment".to_string());
    }
    // userinfo（只记录是否配置，不记录内容）。
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) => (!userinfo.is_empty(), hostport),
        None => (false, rest),
    };
    // IPv6 形式 [::1]:7890，其余 host:port。
    let (host, port_str) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, tail) = inner.split_once(']').ok_or("invalid IPv6 in proxy")?;
        let tail = tail.strip_prefix(':').ok_or("missing port")?;
        (h.to_string(), tail.to_string())
    } else {
        let (h, p) = hostport.rsplit_once(':').ok_or("missing port")?;
        (h.to_string(), p.to_string())
    };
    if host.is_empty() {
        return Err("missing host".to_string());
    }
    let port: u16 = port_str.parse().map_err(|_| "invalid port")?;
    if port == 0 {
        return Err("invalid port".to_string());
    }
    let host_loopback =
        host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    Ok(ValidatedProxy {
        scheme,
        port,
        host_loopback,
        auth,
    })
}

/// 按 HTTP 状态码分类（对齐上游 Python `probe` 的 access 分支）。
/// 纯函数，表驱动单测。
fn classify_probe_status(status: u16) -> &'static str {
    match status {
        401 => "unauthenticated",
        403 | 407 => "access_restricted",
        n if n >= 500 => "server_error",
        _ => "http_response",
    }
}

/// 构造只走**显式代理**的 HTTP 客户端：
/// `.no_proxy()` 禁用系统/环境代理继承，`.proxy()` 仅用指定代理——
/// 对齐上游「no implicit system proxy or direct fallback」。
fn build_proxy_client(proxy_url: &str) -> Result<reqwest::blocking::Client, String> {
    use reqwest::Proxy;
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .connect_timeout(Duration::from_secs(6))
        .user_agent("claude-code/2.1.0")
        .no_proxy()
        .proxy(Proxy::all(proxy_url).map_err(|e| format!("代理配置失败: {e}"))?)
        .build()
        .map_err(|e| format!("初始化 HTTP 客户端失败: {e}"))
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// 探测单个目标，产出报告片段（HTTP 调用在此函数内，分类在 `classify_probe_status`）。
fn probe_target(client: &reqwest::blocking::Client, name: &str, url: &str) -> Value {
    let start = std::time::Instant::now();
    let result = client.get(url).send();
    let elapsed = round2(start.elapsed().as_secs_f64());
    match result {
        Ok(response) => {
            let status = response.status().as_u16();
            json!({
                "name": name,
                "url": url,
                "transport_reached": true,
                "http_status": status,
                "access": classify_probe_status(status),
                "elapsed_seconds": elapsed,
                "error": Value::Null,
            })
        }
        Err(e) => {
            let error = if e.is_timeout() {
                "probe_timeout"
            } else if e.is_connect() {
                "connect_failed"
            } else {
                "transport_failed"
            };
            json!({
                "name": name,
                "url": url,
                "transport_reached": false,
                "http_status": Value::Null,
                "access": "unknown",
                "elapsed_seconds": elapsed,
                "error": error,
            })
        }
    }
}

/// 显式代理的无认证传输可达性诊断（不修改系统、不携带账号凭据）。
pub fn diagnose_proxy(proxy_url: &str) -> Result<Value, String> {
    let mut report = json!({
        "schema_version": 1,
        "mode": "proxy_diagnostics",
        "scope": "unauthenticated_transport_only",
        "account_status": "not_evaluated",
        "leak_protection": "not_evaluated",
        "launch_allowed": Value::Null,
        "application_started": false,
        "system_modified": false,
        "note": "仅验证指定代理到目标的无认证传输可达；401/403 只表示请求已到达服务器，传输到达 ≠ 账号可用",
    });

    let validated = match validate_proxy_url(proxy_url) {
        Ok(v) => v,
        Err(_) => {
            report["state"] = json!("configuration_error");
            report["error"] = json!("invalid_or_missing_proxy");
            report["hint"] = json!("需显式指定带端口的代理 URL（http/https/socks5/socks5h）");
            return Ok(report);
        }
    };

    let client = match build_proxy_client(proxy_url) {
        Ok(c) => c,
        Err(e) => {
            report["state"] = json!("configuration_error");
            report["error"] = json!("proxy_client_build_failed");
            report["detail"] = json!(e);
            return Ok(report);
        }
    };

    let checks = vec![
        probe_target(
            &client,
            "anthropic_api",
            "https://api.anthropic.com/v1/models",
        ),
        probe_target(&client, "claude_web", "https://claude.ai/"),
    ];
    let reached = checks
        .iter()
        .all(|c| c.get("transport_reached").and_then(Value::as_bool) == Some(true));

    report["proxy"] = json!({
        "scheme": validated.scheme,
        "port": validated.port,
        "host_scope": if validated.host_loopback { "loopback" } else { "remote" },
        "authentication_configured": validated.auth,
        "source": "argument",
    });
    report["checks"] = json!(checks);
    report["state"] = json!(if reached {
        "transport_reached"
    } else {
        "transport_failed"
    });
    Ok(report)
}

// ─────────────────────────────────────────────────────────────────────────────
// fingerprint：系统侧指纹 + 虚拟机启发式
// ─────────────────────────────────────────────────────────────────────────────

/// 系统侧设备指纹（GPU/字体/Canvas/WebGL 由前端 webview 补充）。
#[derive(Debug, Clone, Serialize)]
pub struct SystemFingerprint {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub host_name: Option<String>,
    pub cpu_brand: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_frequency_mhz: Option<u64>,
    pub physical_cores: Option<usize>,
    pub total_memory_bytes: u64,
    pub cpu_arch: String,
    /// 是否疑似虚拟机（启发式，命中关键词列表）。
    pub virtual_machine: bool,
    /// 命中的关键词（透明可解释）。
    pub vm_reasons: Vec<String>,
    /// 后端拿不到 GPU 型号，固定 "unknown"，不编造。
    pub gpu: String,
    pub web_notice: String,
}

/// 虚拟机启发式：CPU 型号/主机名/OS 名里命中虚拟化关键词即判为疑似虚拟机。
/// 纯函数，表驱动单测。
fn detect_vm(cpu_brand: &str, host_name: &str, os_name: &str) -> (bool, Vec<String>) {
    const HINTS: [&str; 8] = [
        "vmware",
        "virtualbox",
        "vbox",
        "virtual",
        "hyper-v",
        "hyperv",
        "kvm",
        "qemu",
    ];
    let blob = format!("{cpu_brand} {host_name} {os_name}").to_lowercase();
    let reasons = HINTS
        .iter()
        .filter(|h| blob.contains(**h))
        .map(|h| h.to_string())
        .collect::<Vec<_>>();
    (!reasons.is_empty(), reasons)
}

/// 采集系统侧硬件指纹。
pub fn system_fingerprint() -> SystemFingerprint {
    let mut system = System::new_all();
    system.refresh_cpu_all();
    let cpu = system.cpus().first();
    let cpu_brand = cpu
        .map(|c| c.brand().trim().to_string())
        .filter(|s| !s.is_empty());
    let cpu_vendor = cpu
        .map(|c| c.vendor_id().to_string())
        .filter(|s| !s.is_empty());
    let frequency = cpu.map(|c| c.frequency());
    let host_name = System::host_name().filter(|s| !s.is_empty());
    let os_name = System::name().filter(|s| !s.is_empty());
    let (virtual_machine, vm_reasons) = detect_vm(
        cpu_brand.as_deref().unwrap_or(""),
        host_name.as_deref().unwrap_or(""),
        os_name.as_deref().unwrap_or(""),
    );
    SystemFingerprint {
        os_name,
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
        host_name,
        cpu_brand,
        cpu_vendor,
        cpu_frequency_mhz: frequency,
        physical_cores: system.physical_core_count(),
        total_memory_bytes: system.total_memory(),
        cpu_arch: System::cpu_arch(),
        virtual_machine,
        vm_reasons,
        gpu: "unknown".to_string(),
        web_notice: "字体/GPU/Canvas/WebGL 指纹需在 webview 内通过 Web 检测页采集（后端读不到）"
            .to_string(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// cli-info：Claude Code CLI 只读体检
// ─────────────────────────────────────────────────────────────────────────────

/// PATH 中发现的一份 claude 命令。
#[derive(Debug, Clone, Serialize)]
pub struct CliInstance {
    pub path: String,
    /// 在 PATH 中的顺序（1-based，靠前的优先）。
    pub order: usize,
    pub version: Option<String>,
    pub install_method: String,
}

/// CLI 体检结果。
#[derive(Debug, Clone, Serialize)]
pub struct CliInfo {
    pub found: bool,
    pub instances: Vec<CliInstance>,
    pub warnings: Vec<String>,
    /// `~/.claude` 配置目录存在时给出路径。
    pub config_dir: Option<String>,
}

/// 在 PATH 字符串里按顺序找所有 claude 可执行文件（纯函数：exists 判定注入，
/// 便于表驱动单测）。Windows 识别 claude.exe / claude.cmd，也兼容裸名 claude。
fn find_claude_executables<F: Fn(&Path) -> bool>(path_env: &str, exists: F) -> Vec<String> {
    const EXTENSIONS: [&str; 3] = ["claude.exe", "claude.cmd", "claude"];
    let mut found: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in path_env.split(';') {
        let dir = dir.trim();
        if dir.is_empty() {
            continue;
        }
        for ext in EXTENSIONS {
            let candidate = Path::new(dir).join(ext);
            let key = candidate.to_string_lossy().to_lowercase();
            if seen.contains(&key) {
                continue;
            }
            if exists(&candidate) {
                seen.insert(key);
                found.push(candidate.to_string_lossy().to_string());
            }
        }
    }
    found
}

/// 从 `claude --version` 输出取首行版本（纯函数）。
fn parse_claude_version_output(raw: &str) -> Option<String> {
    let first = raw.lines().find(|l| !l.trim().is_empty())?;
    let v = first.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// 根据可执行路径判断安装方式（纯函数，表驱动单测）。
fn detect_install_method(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.contains("node_modules") && p.contains("claude-code") {
        "npm"
    } else if p.contains(r"\.claude\") || p.contains("/.claude/") || p.contains(".local") {
        "native(官方安装脚本)"
    } else if p.contains("bun") {
        "bun"
    } else {
        "unknown(建议核对 PATH)"
    }
}

/// 真实执行 `claude --version` 取版本（隐藏窗口；拿不到返回 None，不阻塞体检）。
fn run_claude_version(exe: &str) -> Option<String> {
    let output = imp::silent_command(exe).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_claude_version_output(&String::from_utf8_lossy(&output.stdout))
}

/// CLI 只读体检：PATH 中所有 claude 的位置/顺序/版本/安装方式，多份并存告警。
/// 不执行卸载/升级。
pub fn cli_info() -> CliInfo {
    let path_env = std::env::var("PATH").unwrap_or_default();
    let paths_found = find_claude_executables(&path_env, |p| p.exists());
    let mut instances = Vec::new();
    for (i, p) in paths_found.iter().enumerate() {
        instances.push(CliInstance {
            path: p.clone(),
            order: i + 1,
            version: run_claude_version(p),
            install_method: detect_install_method(p).to_string(),
        });
    }
    let mut warnings = Vec::new();
    if instances.len() > 1 {
        warnings.push(format!(
            "检测到 {} 份 claude 命令并存（PATH 靠前的优先）：{}",
            instances.len(),
            instances
                .iter()
                .map(|i| i.path.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    } else if instances.is_empty() {
        warnings.push("PATH 中没有 claude 命令（桌面版可能自带内置 CLI）".to_string());
    }
    let config_dir = paths::home_dir()
        .map(|h| h.join(".claude"))
        .ok()
        .filter(|p| p.is_dir())
        .map(|p| p.to_string_lossy().to_string());
    CliInfo {
        found: !instances.is_empty(),
        instances,
        warnings,
        config_dir,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 单测（全部不依赖真实网络/真实浏览器/真实子进程）
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(name: &str, description: &str, status: &str, ipv4: &[&str]) -> imp::AdapterInfo {
        imp::AdapterInfo {
            name: name.to_string(),
            description: description.to_string(),
            status: status.to_string(),
            if_index: 0,
            ipv4: ipv4.iter().map(|s| s.to_string()).collect(),
            ipv6: Vec::new(),
        }
    }

    #[test]
    fn safe_url_scheme_table() {
        // (输入, 是否接受)
        let cases = [
            ("", false),
            ("http://example.com", true),
            ("https://example.com/login?token=abc", true),
            ("ftp://example.com", false),
            ("file:///etc/passwd", false),
            ("javascript:alert(1)", false),
            ("data:text/html,x", false),
        ];
        for (url, accept) in cases {
            let got = validate_safe_url(url).is_ok();
            assert_eq!(got, accept, "url={url:?}");
        }
        // 错误文案对齐上游。
        assert!(validate_safe_url("file:///x")
            .unwrap_err()
            .contains("只允许 http/https"));
    }

    #[test]
    fn tun_ready_table() {
        let cases = [
            (
                vec![adapter("以太网", "Realtek PCIe", "Up", &["192.168.1.5"])],
                false,
                "物理网卡不算 TUN",
            ),
            (
                vec![adapter(
                    "Mihomo",
                    "Wintun Userspace Tunnel",
                    "Up",
                    &["198.18.0.1"],
                )],
                true,
                "Up + Wintun",
            ),
            (
                vec![adapter(
                    "clash-tun",
                    "TAP-Windows Adapter",
                    "Disabled",
                    &["10.0.0.2"],
                )],
                false,
                "Disabled 不算",
            ),
            (
                vec![adapter(
                    "Tailscale",
                    "Tailscale Tunnel",
                    "Up",
                    &["100.64.0.1"],
                )],
                true,
                "Up + Tailscale",
            ),
            (
                vec![adapter("以太网", "Realtek", "Up", &["198.18.4.5"])],
                true,
                "fake-ip 段即接管",
            ),
        ];
        for (adapters, expect, desc) in cases {
            assert_eq!(tun_ready(&adapters), expect, "{desc}");
        }
    }

    #[test]
    fn open_args_contain_isolation_flags() {
        let profile = Path::new(r"C:\Users\u\.claude-switcher\safe-profiles\abc");
        let args = build_open_args("https://example.com", profile);
        let joined = args.join(" ");
        assert!(
            joined.contains("--user-data-dir=C:\\Users\\u\\.claude-switcher\\safe-profiles\\abc")
        );
        assert!(args.contains(&"--no-first-run".to_string()));
        assert!(args.contains(&"--no-default-browser-check".to_string()));
        assert!(args.contains(&"--disable-extensions".to_string()));
        assert!(
            args.contains(&"--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string())
        );
        assert!(args.iter().any(|a| a == "https://example.com"));
    }

    #[test]
    fn proxy_url_validation_table() {
        // 合法
        let ok = [
            "http://127.0.0.1:7897",
            "socks5h://[::1]:18080",
            "http://user:secret@remote.example:18080",
            "https://localhost:8443",
        ];
        for url in ok {
            let v = validate_proxy_url(url).unwrap_or_else(|e| panic!("应通过: {url} ({e})"));
            assert!(v.port > 0);
        }
        // 摘要不含凭据
        let v = validate_proxy_url("http://user:secret@remote.example:18080").unwrap();
        assert!(v.auth);
        assert_eq!(v.port, 18080);
        assert!(!v.host_loopback);
        // IPv6 loopback
        let v6 = validate_proxy_url("socks5h://[::1]:18080").unwrap();
        assert_eq!(v6.scheme, "socks5h");
        assert!(v6.host_loopback);
        // 非法
        let bad = [
            "file:///secret",
            "http://host:80/path",
            "http://host:80?x=1",
            "http://host:80#frag",
            "http://host",
            "http://host:0",
            "http://host:99999",
            "http://host:abc",
            "http://host:80\nproxy-user=secret",
            "",
        ];
        for url in bad {
            assert!(validate_proxy_url(url).is_err(), "应拒绝: {url:?}");
        }
    }

    #[test]
    fn probe_status_classification_table() {
        assert_eq!(classify_probe_status(200), "http_response");
        assert_eq!(classify_probe_status(401), "unauthenticated");
        assert_eq!(classify_probe_status(403), "access_restricted");
        assert_eq!(classify_probe_status(407), "access_restricted");
        assert_eq!(classify_probe_status(503), "server_error");
    }

    #[test]
    fn diagnose_configuration_error_does_not_echo_secret() {
        // 非法代理 → 结构化 configuration_error，且报告里不含 secret。
        let report = diagnose_proxy("http://user:secret@host:bad").unwrap();
        assert_eq!(report["state"], "configuration_error");
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("host:bad"));
    }

    #[test]
    fn find_claude_executables_table() {
        // 伪造 PATH：dir1 有 claude.cmd，dir2 有 claude.exe，dir3 无。
        let path = r"C:\bin;C:\tools\nodejs;C:\empty";
        let exists = |p: &Path| {
            matches!(
                p.to_str().unwrap_or(""),
                r"C:\bin\claude.cmd" | r"C:\tools\nodejs\claude.exe"
            )
        };
        let found = find_claude_executables(path, exists);
        assert_eq!(found.len(), 2);
        assert!(found[0].ends_with(r"C:\bin\claude.cmd"));
        assert!(found[1].ends_with(r"nodejs\claude.exe"));
        // 无 claude
        let none = find_claude_executables(r"C:\empty", |_| false);
        assert!(none.is_empty());
    }

    #[test]
    fn install_method_table() {
        assert_eq!(
            detect_install_method(r"C:\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"),
            "npm"
        );
        assert_eq!(
            detect_install_method(r"C:\Users\u\.claude\bin\claude.exe"),
            "native(官方安装脚本)"
        );
        assert_eq!(detect_install_method(r"C:\bun\bin\claude.exe"), "bun");
        assert_eq!(
            detect_install_method(r"C:\weird\place\claude.exe"),
            "unknown(建议核对 PATH)"
        );
    }

    #[test]
    fn version_output_parsing() {
        assert_eq!(
            parse_claude_version_output("9.9.9 (Claude Code)\n"),
            Some("9.9.9 (Claude Code)".to_string())
        );
        assert_eq!(parse_claude_version_output(""), None);
        assert_eq!(parse_claude_version_output("\n\n"), None);
    }

    #[test]
    fn vm_detection_table() {
        // 物理机
        let (vm, reasons) = detect_vm(
            "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz",
            "DESKTOP-ABC123",
            "Windows 11",
        );
        assert!(!vm, "物理机不应判为虚拟机, reasons={reasons:?}");
        // VMware
        let (vm, reasons) = detect_vm(
            "Intel(R) Xeon(R) Platinum 8273CL (VMware)",
            "srv",
            "Windows Server 2022",
        );
        assert!(vm && reasons.iter().any(|r| r == "vmware"));
        // VirtualBox 主机名
        let (vm, reasons) = detect_vm("AMD Ryzen 5", "DESKTOP-VBOX42", "Windows 10");
        assert!(vm && reasons.iter().any(|r| r == "vbox"));
    }
}
