//! 应用级持久化配置（`~/.claude-switcher/appconfig.json`）。
//!
//! 与账号快照（store.rs）分离：这里存的是**全局环境/代理偏好**，
//! 供 region / guard / rules / checks / diagnostics 等模块共享，
//! 避免多个模块争用 store.rs。读写一律走原子写（fsx）。

use serde::{Deserialize, Serialize};

use crate::fsx;
use crate::paths;

/// 全局环境与代理偏好。所有字段可选，缺省走默认/自动探测。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    /// **P1-03**：配置 schema 版本（用于迁移）。
    /// 0/缺失 = 旧版（首次引入版本号的配置）。
    #[serde(default)]
    pub schema_version: u32,
    /// 目标国家码（如 "US"、"JP"），由出口 IP 锁定。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_target: Option<String>,
    /// 目标 Windows 时区 ID（如 "Eastern Standard Time"）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tz_target: Option<String>,
    /// 目标区域格式（如 "en-US"）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locale_target: Option<String>,
    /// 代理客户端：clash-verge/sing-box/clashx/surge/wireguard/other/auto。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_mode: Option<String>,
    /// Clash 选择组名（Clash Verge 模式用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_group: Option<String>,
    /// WebRTC 策略：proxy / reject。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webrtc_policy: Option<String>,
    /// 最近一次出口 IPv4（用于「IP 一致」检查）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_egress_ip: Option<String>,
    /// P2-1：额度阈值提醒（当前账号达阈值时提醒 + 一键切换），**默认关闭**。
    /// 只做提醒，不做后台自动换号。
    #[serde(default)]
    pub quota_reminder_enabled: bool,
    /// P2-1：提醒阈值（百分比，默认 90）。
    #[serde(default = "default_quota_reminder_threshold")]
    pub quota_reminder_threshold: u8,
    /// H-6：切换前对账遇到未登记账号时是否自动收养（默认开）。
    /// 关闭时只提示「检测到未登记账号」，不自动新建账号。
    #[serde(default = "default_auto_adopt_enabled")]
    pub auto_adopt_enabled: bool,
    /// F-6：WSL 集成实验开关，**默认关闭**。仅在用户显式开启并选择发行版后，
    /// 才向该 WSL 发行版写入凭据；不开启则不做任何 WSL 操作。
    #[serde(default)]
    pub wsl_integration_enabled: bool,
    /// 出口门禁（融合 ClaudeGuard）：被监控的出口链路目标表。
    /// 空表示未配置；内置默认表由 [`crate::egate_defaults`] 提供。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egate_targets: Vec<crate::egate::EgateTarget>,
    /// 出口门禁总开关（默认关：这是「持续校验 + 熔断」能力，需用户显式启用）。
    #[serde(default)]
    pub egate_enabled: bool,
    /// 熔断防抖阈值：连续 N 次失败才熔断（默认 2，0 表示关闭熔断）。
    #[serde(default = "default_egate_trip_threshold")]
    pub egate_trip_threshold: u32,
    /// 检查间隔秒数（下限 5，上限 3600；默认 15）。
    #[serde(default = "default_egate_interval")]
    pub egate_interval_secs: u64,
    /// 是否启用「接入路径检查」：未接入代理链路时跳过探测并按阈值处理（默认开）。
    #[serde(default = "default_egate_enforce_access")]
    pub egate_enforce_access: bool,
    /// 被守护的桌面应用 id（claude / chatgpt / antigravity）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egate_guarded_agents: Vec<String>,
    /// 是否启用本地日志（默认开启）。
    /// 关闭后不写 `~/.claude-switcher/logs/`，但排障线索也丢失。
    #[serde(default = "default_true")]
    pub log_enabled: bool,
    /// 日志级别：error / info / debug（默认 info）。
    /// error 只记录错误，info 记录错误 + 非错误事件，debug 全记录。
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// 已关闭的检查项 key 列表（如 ["webrtc","asn"]）。
    /// 核心保护项（proxy_core / tun / egress_country / guard）不允许关闭。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disabled_checks: Vec<String>,
    /// 发现绕过代理的直连时是否**熔断**（默认只告警）。
    ///
    /// 默认关闭：直连判定依赖 TCP 连接表，某些正常场景（应用更新、遥测）也会
    /// 出现公网连接，直接熔断可能误杀。开启前用户应确认自己的网络结构。
    #[serde(default)]
    pub egate_leak_trip: bool,
}

/// 熔断默认连续 2 次失败（单次网络抖动不熔断）。
fn default_egate_trip_threshold() -> u32 {
    2
}

/// 默认 15 秒复查一次。
fn default_egate_interval() -> u64 {
    15
}

/// 默认启用接入路径检查。
fn default_egate_enforce_access() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

/// H-6：自动收养默认开启。
fn default_auto_adopt_enabled() -> bool {
    true
}

/// P2-1 默认提醒阈值 90%。
fn default_quota_reminder_threshold() -> u8 {
    90
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            country_target: None,
            tz_target: None,
            locale_target: None,
            proxy_mode: None,
            proxy_group: None,
            webrtc_policy: None,
            last_egress_ip: None,
            quota_reminder_enabled: false,
            // 与 serde default 保持一致（90），否则缺字段解析与 Default 不一致。
            quota_reminder_threshold: default_quota_reminder_threshold(),
            auto_adopt_enabled: default_auto_adopt_enabled(),
            wsl_integration_enabled: false,
            egate_targets: Vec::new(),
            egate_enabled: false,
            egate_trip_threshold: default_egate_trip_threshold(),
            egate_interval_secs: default_egate_interval(),
            egate_enforce_access: default_egate_enforce_access(),
            egate_guarded_agents: Vec::new(),
            egate_leak_trip: false,
            disabled_checks: Vec::new(),
            log_enabled: true,
            log_level: default_log_level(),
        }
    }
}

/// **P1-03**：当前配置 schema 版本。
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// **P1-03**：按版本迁移配置（纯函数，保留未知字段由 serde 默认值兜底）。
///
/// 返回 `(迁移后配置, 是否发生迁移)`。迁移失败返回 Err，调用方**不得**
/// 用默认配置覆盖原文件。
pub fn migrate(mut config: AppConfig) -> Result<(AppConfig, bool), String> {
    let from = config.schema_version;
    if from > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "配置版本 {from} 高于本程序支持的 {CURRENT_SCHEMA_VERSION}（可能来自更新版本），已拒绝加载以免降级覆盖"
        ));
    }
    if from == CURRENT_SCHEMA_VERSION {
        return Ok((config, false));
    }
    // v0 → v1：仅补版本号（其余字段由 serde default 处理，已有值保持不变）。
    // 未来版本在此逐级迁移。
    config.schema_version = CURRENT_SCHEMA_VERSION;
    Ok((config, true))
}

/// **P1-03**：严格加载 + 迁移（升级前先备份原文件）。
fn load_from_migrated(path: &std::path::Path) -> Result<AppConfig, String> {
    let config = load_from(path)?;
    let (migrated, changed) = migrate(config)?;
    if changed {
        // 迁移前备份原始文件（时间戳后缀，不覆盖）。
        let backup = path.with_extension(format!(
            "json.bak-{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ));
        std::fs::copy(path, &backup).map_err(|e| format!("迁移前备份配置失败：{e}"))?;
        // 只在迁移成功后写入新版本。
        let text = serde_json::to_string_pretty(&migrated)
            .map_err(|e| format!("序列化迁移后配置失败：{e}"))?;
        crate::fsx::write_atomically(path, &text)
            .map_err(|e| format!("写入迁移后配置失败：{e}"))?;
    }
    Ok(migrated)
}

fn config_path() -> Result<std::path::PathBuf, String> {
    Ok(paths::app_data_dir()?.join("appconfig.json"))
}

/// 读取配置供界面展示；错误会记录，原文件保持可恢复状态。
pub fn load() -> AppConfig {
    match config_path().and_then(|path| load_from(&path)) {
        Ok(config) => config,
        Err(error) => {
            crate::log_error(&format!(
                "应用配置读取失败，本次展示默认值，原文件已保留：{error}"
            ));
            AppConfig::default()
        }
    }
}

fn load_from(path: &std::path::Path) -> Result<AppConfig, String> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AppConfig::default())
        }
        Err(error) => return Err(format!("读取应用配置失败：{error}")),
    };
    let text = crate::jsonio::decode_text(&bytes);
    serde_json::from_str(&text)
        .map_err(|error| format!("应用配置格式无效，请先修复配置文件：{error}"))
}

/// 配置加载的严格结果（区分三种状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigLoad {
    /// 正常读取。
    Ok(Box<AppConfig>),
    /// 首次安装（文件不存在）。
    Fresh,
    /// 配置损坏或无法读取（**不得**当成用户主动关闭）。
    Corrupt(String),
}

/// **P0-12**：严格加载配置，区分「首次安装」「正常读取」「配置损坏」。
///
/// 门禁监控、恢复器和受保护启动入口必须用这个版本——用 `load()` 的默认值
/// 兜底会让「已启用保护的用户遇到配置损坏」被静默降级为「用户主动关闭」。
pub fn load_checked() -> ConfigLoad {
    let path = match config_path() {
        Ok(path) => path,
        Err(error) => return ConfigLoad::Corrupt(format!("无法定位配置文件：{error}")),
    };
    if !path.exists() {
        return ConfigLoad::Fresh;
    }
    match load_from_migrated(&path) {
        Ok(config) => ConfigLoad::Ok(Box::new(config)),
        Err(error) => ConfigLoad::Corrupt(error),
    }
}

/// 在跨进程排他锁内完成读取、修改和原子保存。
/// 闭包只修改传入配置，不得再次调用 update。
pub fn update(mut f: impl FnMut(&mut AppConfig)) -> Result<AppConfig, String> {
    let path = config_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| "应用配置缺少父目录".to_string())?;
    std::fs::create_dir_all(parent).map_err(|error| format!("创建配置目录失败：{error}"))?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path.with_extension("lock"))
        .map_err(|error| format!("打开配置锁失败：{error}"))?;
    fs4::FileExt::lock(&lock).map_err(|error| format!("获取配置锁失败：{error}"))?;
    // **P1-02**：写入路径也走迁移——避免旧程序把高版本配置覆盖成旧结构。
    let mut config = load_from_migrated(&path)?;
    f(&mut config);
    let text = serde_json::to_string_pretty(&config)
        .map_err(|error| format!("序列化应用配置失败：{error}"))?;
    fsx::write_atomically(&path, &text).map_err(|error| format!("保存应用配置失败：{error}"))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_preserves_invalid_configuration_and_does_not_run_the_change() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        let path = config_path().unwrap();
        assert_eq!(path, dir.path().join(".claude-switcher/appconfig.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "invalid configuration, preserve").unwrap();
        let mut called = false;
        assert!(update(|cfg| {
            called = true;
            cfg.country_target = Some("JP".into());
        })
        .is_err());
        assert!(!called);
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "invalid configuration, preserve"
        );
    }

    #[test]
    fn concurrent_updates_retain_every_change() {
        let _lock = crate::test_support::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::test_support::set_env("USERPROFILE", dir.path());
        update(|cfg| cfg.country_target = Some("JP".into())).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    update(|cfg| {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        cfg.quota_reminder_threshold += 1;
                    })
                    .unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let result = load();
        assert_eq!(result.quota_reminder_threshold, 98);
        assert_eq!(result.country_target.as_deref(), Some("JP"));
    }

    #[test]
    fn missing_file_yields_default() {
        let dir = tempfile::tempdir().unwrap();
        let parsed = load_from(&dir.path().join("missing.json")).unwrap();
        assert_eq!(parsed, AppConfig::default());
    }

    #[test]
    fn round_trips_fields() {
        let cfg = AppConfig {
            country_target: Some("US".to_string()),
            proxy_mode: Some("clash-verge".to_string()),
            webrtc_policy: Some("reject".to_string()),
            ..Default::default()
        };
        let text = serde_json::to_string(&cfg).expect("serialize");
        let back: AppConfig = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[test]
    fn egate_settings_round_trip_without_losing_targets() {
        let mut cfg = AppConfig {
            egate_enabled: true,
            egate_trip_threshold: 3,
            egate_interval_secs: 30,
            egate_enforce_access: false,
            egate_guarded_agents: vec!["claude".to_string()],
            egate_targets: crate::egate_defaults::builtin_targets(),
            ..Default::default()
        };
        cfg.egate_targets[1].expect_ips = vec!["1.2.3.4".to_string()];
        cfg.egate_targets[1].expect_regions = vec!["US".to_string()];
        let text = serde_json::to_string(&cfg).expect("serialize");
        let back: AppConfig = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(cfg, back);
        // 目标表必须逐字段完整保留，不能只剩 id/name。
        assert_eq!(
            back.egate_targets[1].anchor_url,
            cfg.egate_targets[1].anchor_url
        );
        assert_eq!(
            back.egate_targets[1].anchor_kind,
            cfg.egate_targets[1].anchor_kind
        );
        assert_eq!(
            back.egate_targets[1].expect_ips,
            vec!["1.2.3.4".to_string()]
        );
        assert_eq!(back.egate_targets[1].expect_regions, vec!["US".to_string()]);
        assert!(back.egate_targets[2].enabled, "启用状态必须保留");
        assert!(!back.egate_targets[0].enabled, "local 默认关闭必须保留");
    }

    #[test]
    fn egate_fields_default_safely_when_absent() {
        // 旧版 appconfig.json 没有 egate 字段：必须安全降级为「门禁关闭、无目标」，
        // 而不是解析失败把整份配置丢掉。
        let old = r#"{"country_target":"US","wsl_integration_enabled":false}"#;
        let cfg: AppConfig = serde_json::from_str(old).unwrap();
        assert!(!cfg.egate_enabled, "缺字段时必须默认关闭门禁");
        assert!(cfg.egate_targets.is_empty());
        assert_eq!(cfg.egate_trip_threshold, 2, "阈值默认 2");
        assert_eq!(cfg.egate_interval_secs, 15, "间隔默认 15 秒");
        assert!(cfg.egate_enforce_access, "接入检查默认开启");
        assert_eq!(cfg.country_target.as_deref(), Some("US"), "旧字段不能丢");
    }

    #[test]
    fn strict_loader_rejects_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(load_from(&path).is_err());
    }
}
