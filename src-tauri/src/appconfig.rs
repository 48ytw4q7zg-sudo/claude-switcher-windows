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
        }
    }
}

fn config_path() -> Result<std::path::PathBuf, String> {
    Ok(paths::app_data_dir()?.join("appconfig.json"))
}

/// 读取配置；文件不存在时返回默认。
///
/// **文件损坏时不静默回默认**：记一条日志说明原内容未被采用，且不会自动重写
/// （要等某次 `update()` 才会整体覆盖）。静默回退会让用户以为地区/代理设置
/// 还在，实际已被默认值取代，排障时毫无线索。
pub fn load() -> AppConfig {
    match config_path() {
        Ok(path) if path.exists() => match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<AppConfig>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    crate::log_error(&format!(
                        "appconfig.json 解析失败，本次按默认配置运行（{}）；\
                         下次保存设置会整体覆盖该文件",
                        e
                    ));
                    AppConfig::default()
                }
            },
            Err(e) => {
                crate::log_error(&format!("appconfig.json 读取失败，按默认配置运行: {e}"));
                AppConfig::default()
            }
        },
        _ => AppConfig::default(),
    }
}

/// 原子写入配置。
pub fn save(config: &AppConfig) -> Result<(), String> {
    let path = config_path()?;
    let text =
        serde_json::to_string_pretty(config).map_err(|e| format!("序列化 appconfig 失败: {e}"))?;
    fsx::write_atomically(&path, &text).map_err(|e| format!("写入 appconfig 失败: {e}"))
}

/// 在当前配置上原地修改并原子保存，返回更新后的配置。
pub fn update(mut f: impl FnMut(&mut AppConfig)) -> Result<AppConfig, String> {
    let mut config = load();
    f(&mut config);
    save(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_yields_default() {
        let parsed: AppConfig = serde_json::from_str("{}").unwrap_or_default();
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
    fn tolerates_garbage_via_default() {
        let parsed: AppConfig = serde_json::from_str("not json").unwrap_or_default();
        assert_eq!(parsed, AppConfig::default());
    }
}
