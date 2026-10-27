//! 地区目标（国家 / 时区 / 区域格式 / Windows GeoID）映射与锁定。
//!
//! 本模块为纯逻辑层：给定出口国家码（两位 ISO-3166-1 alpha-2）与 ipinfo 返回的
//! IANA 时区名，产出一份用于「锁定 Windows 系统地区」的计划（[`RegionPlan`]）。
//! 不做任何系统调用——真正写时区、写区域格式、设置 GeoID 由调用方（`platform/windows`）
//! 在提权后执行。
//!
//! 行为基准：
//! - 国家 → locale 映射来自上游 `core/claude-switch.sh` 的 `locale_for()`：
//!   US→en_US、JP→ja_JP、TW→zh_TW、HK→zh_HK、SG→en_SG、GB→en_GB、
//!   DE→de_DE、FR→fr_FR、KR→ko_KR、AU→en_AU、CA→en_CA，其余→en_US。
//!   Windows 上区域格式名采用 BCP-47 连字符形式（`en-US` 而非 `en_US`）。
//! - IANA 时区 → Windows 时区 ID 来自上游 `windows/install.ps1` 的 `$tzMap`，
//!   并扩展到常见大都市时区。
//! - GeoID 为微软稳定常量（`GetUserGeoID` / `SetUserGeoID`）：US=244、JP=122、
//!   TW=237、HK=103、SG=208、GB=242、DE=94、FR=84、KR=116、AU=12、CA=39。
//!   未知国家回退美国（244）。

/// 一次「按出口 IP 锁定地区」的完整计划。
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct RegionPlan {
    /// 两位大写国家码（归一后），如 `US`。
    pub country: String,
    /// ipinfo 返回的 IANA 时区名，如 `America/New_York`。
    pub iana_tz: String,
    /// 传给 `Set-TimeZone -Id` / Win32 `SetTimeInformation` 的 Windows 时区 ID。
    pub windows_tz: String,
    /// BCP-47 区域格式，如 `en-US`。
    pub locale: String,
    /// Windows GeoID（`SetUserGeoID`）。
    pub geo_id: u32,
}

/// 已知国家 → Windows GeoID（微软稳定常量）。
///
/// 这些值来自 `Win32_NtLogon` / `GetUserGeoID` 文档与历史 Windows 安装镜像，
/// 跨 Windows 10/11 稳定。如未来某值被微软调整，只需改这张表。
const GEO_TABLE: &[(&str, u32)] = &[
    ("US", 244), // 美国
    ("JP", 122), // 日本
    ("TW", 237), // 台湾
    ("HK", 103), // 香港
    ("SG", 208), // 新加坡
    ("GB", 242), // 英国
    ("DE", 94),  // 德国
    ("FR", 84),  // 法国
    ("KR", 116), // 韩国
    ("AU", 12),  // 澳大利亚
    ("CA", 39),  // 加拿大
];

/// 未知国家的回退 GeoID（美国）。
const GEO_FALLBACK: u32 = 244;

/// 已知国家 → BCP-47 区域格式。
///
/// 对应上游 `locale_for()`，但 `_` 改写为 `-` 以匹配 Windows 区域格式名。
const LOCALE_TABLE: &[(&str, &str)] = &[
    ("US", "en-US"),
    ("JP", "ja-JP"),
    ("TW", "zh-TW"),
    ("HK", "zh-HK"),
    ("SG", "en-SG"),
    ("GB", "en-GB"),
    ("DE", "de-DE"),
    ("FR", "fr-FR"),
    ("KR", "ko-KR"),
    ("AU", "en-AU"),
    ("CA", "en-CA"),
];

/// 未知国家的回退区域格式（美国英语）。
const LOCALE_FALLBACK: &str = "en-US";

/// IANA 时区名 → Windows 时区 ID 表。
///
/// 覆盖安装脚本 `$tzMap` 全部条目，并扩展常见大都市时区。
/// 未知条目回退 [`TZ_FALLBACK`]（`UTC`）。
const IANA_TZ_TABLE: &[(&str, &str)] = &[
    // --- 北美 ---
    ("America/New_York", "Eastern Standard Time"),
    ("America/Detroit", "Eastern Standard Time"),
    ("America/Toronto", "Eastern Standard Time"),
    ("America/Montreal", "Eastern Standard Time"),
    ("America/Indiana/Indianapolis", "Eastern Standard Time"),
    ("America/Chicago", "Central Standard Time"),
    ("America/Winnipeg", "Central Standard Time"),
    ("America/Mexico_City", "Central Standard Time"),
    ("America/Denver", "Mountain Standard Time"),
    ("America/Edmonton", "Mountain Standard Time"),
    ("America/Phoenix", "US Mountain Standard Time"),
    ("America/Los_Angeles", "Pacific Standard Time"),
    ("America/Vancouver", "Pacific Standard Time"),
    ("America/Tijuana", "Pacific Standard Time"),
    ("America/Anchorage", "Alaskan Standard Time"),
    ("Pacific/Honolulu", "Hawaiian Standard Time"),
    // --- 南美 ---
    ("America/Sao_Paulo", "E. South America Standard Time"),
    ("America/Argentina/Buenos_Aires", "Argentina Standard Time"),
    // --- 东亚 / 东南亚 ---
    ("Asia/Tokyo", "Tokyo Standard Time"),
    ("Asia/Seoul", "Korean Standard Time"),
    ("Asia/Pyongyang", "Korean Standard Time"),
    ("Asia/Shanghai", "China Standard Time"),
    ("Asia/Beijing", "China Standard Time"),
    ("Asia/Urumqi", "China Standard Time"),
    ("Asia/Hong_Kong", "China Standard Time"),
    ("Asia/Macau", "China Standard Time"),
    ("Asia/Taipei", "Taipei Standard Time"),
    ("Asia/Singapore", "Singapore Standard Time"),
    ("Asia/Kuala_Lumpur", "Singapore Standard Time"),
    ("Asia/Brunei", "Singapore Standard Time"),
    ("Asia/Manila", "Philippines Standard Time"),
    ("Asia/Bangkok", "SE Asia Standard Time"),
    ("Asia/Jakarta", "SE Asia Standard Time"),
    ("Asia/Ho_Chi_Minh", "SE Asia Standard Time"),
    ("Asia/Novosibirsk", "N. Central Asia Standard Time"),
    // --- 南亚 / 中东 ---
    ("Asia/Kolkata", "India Standard Time"),
    ("Asia/Calcutta", "India Standard Time"),
    ("Asia/Dhaka", "India Standard Time"),
    ("Asia/Karachi", "Pakistan Standard Time"),
    ("Asia/Almaty", "Central Asia Standard Time"),
    ("Asia/Dubai", "Arabian Standard Time"),
    ("Asia/Abu_Dhabi", "Arabian Standard Time"),
    ("Asia/Tehran", "Iran Standard Time"),
    ("Asia/Jerusalem", "Israel Standard Time"),
    ("Asia/Gaza", "Egypt Standard Time"),
    // --- 欧洲 ---
    ("Europe/London", "GMT Standard Time"),
    ("Europe/Dublin", "GMT Standard Time"),
    ("Europe/Lisbon", "GMT Standard Time"),
    ("UTC", "UTC"),
    ("Etc/UTC", "UTC"),
    ("Etc/GMT", "UTC"),
    ("Europe/Berlin", "W. Europe Standard Time"),
    ("Europe/Amsterdam", "W. Europe Standard Time"),
    ("Europe/Vienna", "W. Europe Standard Time"),
    ("Europe/Zurich", "W. Europe Standard Time"),
    ("Europe/Rome", "W. Europe Standard Time"),
    ("Europe/Stockholm", "W. Europe Standard Time"),
    ("Europe/Paris", "Romance Standard Time"),
    ("Europe/Brussels", "Romance Standard Time"),
    ("Europe/Copenhagen", "Romance Standard Time"),
    ("Europe/Madrid", "Romance Standard Time"),
    ("Europe/Athens", "GTB Standard Time"),
    ("Europe/Bucharest", "GTB Standard Time"),
    ("Europe/Helsinki", "FLE Standard Time"),
    ("Europe/Kyiv", "FLE Standard Time"),
    ("Europe/Riga", "FLE Standard Time"),
    ("Europe/Tallinn", "FLE Standard Time"),
    ("Europe/Vilnius", "FLE Standard Time"),
    ("Europe/Sofia", "FLE Standard Time"),
    ("Europe/Minsk", "Belarus Standard Time"),
    ("Europe/Moscow", "Russian Standard Time"),
    ("Europe/Istanbul", "Turkey Standard Time"),
    // --- 非洲 ---
    ("Africa/Cairo", "Egypt Standard Time"),
    ("Africa/Johannesburg", "South Africa Standard Time"),
    ("Africa/Lagos", "W. Central Africa Standard Time"),
    // --- 大洋洲 ---
    ("Australia/Sydney", "AUS Eastern Standard Time"),
    ("Australia/Melbourne", "AUS Eastern Standard Time"),
    ("Australia/Brisbane", "E. Australia Standard Time"),
    ("Australia/Adelaide", "Cen. Australia Standard Time"),
    ("Australia/Perth", "W. Australia Standard Time"),
    ("Pacific/Auckland", "New Zealand Standard Time"),
];

/// 未知 IANA 时区回退的 Windows ID。
const TZ_FALLBACK: &str = "UTC";

/// 把两位国家码归一为大写 trim 后的字符串。
fn normalize_country(country: &str) -> String {
    country.trim().to_uppercase()
}

/// 查静态表，返回 `&'static str`。
fn lookup<'t>(table: &[(&'t str, &'t str)], key: &str) -> Option<&'t str> {
    table
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| *v)
}

/// 给定两位国家码，返回对应的 BCP-47 区域格式（如 `en-US`）。
///
/// 未知国家回退 [`LOCALE_FALLBACK`]（`en-US`）。大小写不敏感。
pub fn locale_for_country(country: &str) -> &'static str {
    lookup(LOCALE_TABLE, country.trim()).unwrap_or(LOCALE_FALLBACK)
}

/// 给定两位国家码，返回对应的 Windows GeoID。
///
/// 未知国家回退 [`GEO_FALLBACK`]（244，美国）。大小写不敏感。
pub fn geo_id_for_country(country: &str) -> u32 {
    GEO_TABLE
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(country.trim()))
        .map(|(_, v)| *v)
        .unwrap_or(GEO_FALLBACK)
}

/// 给定 IANA 时区名（如 `Asia/Tokyo`），返回 Windows 时区 ID（如 `Tokyo Standard Time`）。
///
/// 未知时区回退 [`TZ_FALLBACK`]（`UTC`）。大小写不敏感。
pub fn iana_to_windows_tz(iana: &str) -> &'static str {
    lookup(IANA_TZ_TABLE, iana.trim()).unwrap_or(TZ_FALLBACK)
}

/// 根据出口国家与 ipinfo 返回的 IANA 时区，构造一份完整的地区锁定计划。
///
/// - `country`：两位国家码，允许小写/带空白，内部归一为大写。
/// - `iana_tz`：ipinfo `timezone` 字段，如 `America/New_York`；为空或未知时
///   `windows_tz` 回退 `UTC`。
///
/// 本函数不做网络、不做系统调用，纯计算。
pub fn plan_for_egress(country: &str, iana_tz: &str) -> RegionPlan {
    let normalized = normalize_country(country);
    let iana = iana_tz.trim().to_string();
    RegionPlan {
        windows_tz: iana_to_windows_tz(&iana).to_string(),
        locale: locale_for_country(&normalized).to_string(),
        geo_id: geo_id_for_country(&normalized),
        country: normalized,
        iana_tz: iana,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eleven_countries_plan_correctly() {
        // (country, representative iana, expected windows_tz, expected locale, expected geo_id)
        let cases: &[(&str, &str, &str, &str, u32)] = &[
            (
                "US",
                "America/New_York",
                "Eastern Standard Time",
                "en-US",
                244,
            ),
            ("JP", "Asia/Tokyo", "Tokyo Standard Time", "ja-JP", 122),
            ("TW", "Asia/Taipei", "Taipei Standard Time", "zh-TW", 237),
            ("HK", "Asia/Hong_Kong", "China Standard Time", "zh-HK", 103),
            (
                "SG",
                "Asia/Singapore",
                "Singapore Standard Time",
                "en-SG",
                208,
            ),
            ("GB", "Europe/London", "GMT Standard Time", "en-GB", 242),
            (
                "DE",
                "Europe/Berlin",
                "W. Europe Standard Time",
                "de-DE",
                94,
            ),
            ("FR", "Europe/Paris", "Romance Standard Time", "fr-FR", 84),
            ("KR", "Asia/Seoul", "Korean Standard Time", "ko-KR", 116),
            (
                "AU",
                "Australia/Sydney",
                "AUS Eastern Standard Time",
                "en-AU",
                12,
            ),
            (
                "CA",
                "America/Toronto",
                "Eastern Standard Time",
                "en-CA",
                39,
            ),
        ];
        for (c, iana, wtz, loc, geo) in cases {
            let plan = plan_for_egress(c, iana);
            assert_eq!(plan.country, *c, "country mismatch for {c}");
            assert_eq!(plan.iana_tz, *iana, "iana_tz mismatch for {c}");
            assert_eq!(plan.windows_tz, *wtz, "windows_tz mismatch for {c}");
            assert_eq!(plan.locale, *loc, "locale mismatch for {c}");
            assert_eq!(plan.geo_id, *geo, "geo_id mismatch for {c}");
        }
    }

    #[test]
    fn country_is_normalized_to_uppercase() {
        let plan = plan_for_egress("  jp ", "Asia/Tokyo");
        assert_eq!(plan.country, "JP");
        assert_eq!(plan.locale, "ja-JP");
        assert_eq!(plan.geo_id, 122);
    }

    #[test]
    fn unknown_country_falls_back_to_us() {
        let plan = plan_for_egress("XX", "Europe/Berlin");
        assert_eq!(plan.country, "XX"); // 保留原值，不臆造
        assert_eq!(plan.locale, "en-US");
        assert_eq!(plan.geo_id, 244);
        // 时区仍按 IANA 走，不因为国家未知而改时区
        assert_eq!(plan.windows_tz, "W. Europe Standard Time");
    }

    #[test]
    fn empty_iana_falls_back_to_utc() {
        let plan = plan_for_egress("US", "");
        assert_eq!(plan.iana_tz, "");
        assert_eq!(plan.windows_tz, "UTC");
    }

    #[test]
    fn unknown_iana_falls_back_to_utc() {
        assert_eq!(iana_to_windows_tz("Mars/Olympus"), "UTC");
        assert_eq!(iana_to_windows_tz(""), "UTC");
    }

    #[test]
    fn iana_mapping_is_representative_and_case_insensitive() {
        let cases: &[(&str, &str)] = &[
            ("America/New_York", "Eastern Standard Time"),
            ("America/Los_Angeles", "Pacific Standard Time"),
            ("America/Chicago", "Central Standard Time"),
            ("America/Denver", "Mountain Standard Time"),
            ("America/Phoenix", "US Mountain Standard Time"),
            ("America/Anchorage", "Alaskan Standard Time"),
            ("Pacific/Honolulu", "Hawaiian Standard Time"),
            ("Asia/Tokyo", "Tokyo Standard Time"),
            ("Asia/Seoul", "Korean Standard Time"),
            ("Asia/Taipei", "Taipei Standard Time"),
            ("Asia/Hong_Kong", "China Standard Time"),
            ("Asia/Singapore", "Singapore Standard Time"),
            ("Asia/Shanghai", "China Standard Time"),
            ("Europe/London", "GMT Standard Time"),
            ("Europe/Berlin", "W. Europe Standard Time"),
            ("Europe/Paris", "Romance Standard Time"),
            ("Europe/Madrid", "Romance Standard Time"),
            ("Europe/Rome", "W. Europe Standard Time"),
            ("Europe/Moscow", "Russian Standard Time"),
            ("Australia/Sydney", "AUS Eastern Standard Time"),
            ("Australia/Melbourne", "AUS Eastern Standard Time"),
            ("Australia/Brisbane", "E. Australia Standard Time"),
            ("Australia/Perth", "W. Australia Standard Time"),
            ("Pacific/Auckland", "New Zealand Standard Time"),
            ("UTC", "UTC"),
            ("Etc/UTC", "UTC"),
        ];
        for (iana, expected) in cases {
            assert_eq!(iana_to_windows_tz(iana), *expected, "mapping for {iana}");
            // 大小写不敏感
            let lower = iana.to_lowercase();
            assert_eq!(
                iana_to_windows_tz(&lower),
                *expected,
                "case-insensitive mapping for {iana}"
            );
        }
    }

    #[test]
    fn locale_for_country_covers_all_known() {
        assert_eq!(locale_for_country("US"), "en-US");
        assert_eq!(locale_for_country("jp"), "ja-JP");
        assert_eq!(locale_for_country("TW"), "zh-TW");
        assert_eq!(locale_for_country("HK"), "zh-HK");
        assert_eq!(locale_for_country("SG"), "en-SG");
        assert_eq!(locale_for_country("GB"), "en-GB");
        assert_eq!(locale_for_country("DE"), "de-DE");
        assert_eq!(locale_for_country("FR"), "fr-FR");
        assert_eq!(locale_for_country("KR"), "ko-KR");
        assert_eq!(locale_for_country("AU"), "en-AU");
        assert_eq!(locale_for_country("CA"), "en-CA");
        assert_eq!(locale_for_country("__unknown__"), "en-US");
    }

    #[test]
    fn geo_id_for_country_covers_all_known() {
        assert_eq!(geo_id_for_country("US"), 244);
        assert_eq!(geo_id_for_country("jp"), 122);
        assert_eq!(geo_id_for_country("TW"), 237);
        assert_eq!(geo_id_for_country("HK"), 103);
        assert_eq!(geo_id_for_country("SG"), 208);
        assert_eq!(geo_id_for_country("GB"), 242);
        assert_eq!(geo_id_for_country("DE"), 94);
        assert_eq!(geo_id_for_country("FR"), 84);
        assert_eq!(geo_id_for_country("KR"), 116);
        assert_eq!(geo_id_for_country("AU"), 12);
        assert_eq!(geo_id_for_country("CA"), 39);
        assert_eq!(geo_id_for_country("__unknown__"), 244);
    }

    #[test]
    fn region_plan_is_serializable_and_clonable() {
        let plan = plan_for_egress("US", "America/New_York");
        let cloned = plan.clone();
        assert_eq!(plan, cloned);
        let json = serde_json::to_string(&cloned).expect("serialize");
        assert!(json.contains("Eastern Standard Time"));
        assert!(json.contains("en-US"));
        assert!(json.contains("\"geo_id\":244"));
    }
}
