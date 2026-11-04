//! 受支持的出口地区（产品约束：只允许新加坡 / 日本 / 美国）。
//!
//! 这是**产品决定**，不是技术限制：地区锁、时区对齐、出口白名单都只在这三个
//! 国家之间切换。把它集中在常量表里，后端校验与前端选择器共用同一份定义，
//! 避免「界面能选、后端拒绝」或反过来的漂移。
//!
//! 为什么美国要列出多个时区：美国是多时区国家，「出口美国」并不能推出唯一时区；
//! 这里给出常用时区供用户选，而不是猜一个。

use serde::Serialize;

/// 一个受支持地区。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupportedRegion {
    /// ISO alpha-2 国家码。
    pub country: &'static str,
    /// 中文名。
    pub name: &'static str,
    /// 该国可选的默认 Windows 时区（第一项为推荐值）。
    pub timezones: &'static [&'static str],
    /// BCP-47 区域格式。
    pub locale: &'static str,
}

/// 受支持地区的唯一真源。
pub const SUPPORTED_REGIONS: &[SupportedRegion] = &[
    SupportedRegion {
        country: "SG",
        name: "新加坡",
        timezones: &["Singapore Standard Time"],
        locale: "en-SG",
    },
    SupportedRegion {
        country: "JP",
        name: "日本",
        timezones: &["Tokyo Standard Time"],
        locale: "ja-JP",
    },
    SupportedRegion {
        country: "US",
        name: "美国",
        // 多时区国家：给出常用时区，由用户明确选择，不替他猜。
        timezones: &[
            "Pacific Standard Time",
            "Eastern Standard Time",
            "Central Standard Time",
            "Mountain Standard Time",
        ],
        locale: "en-US",
    },
];

/// 该国家是否在受支持列表内（大小写不敏感）。
pub fn is_supported_country(country: &str) -> bool {
    let country = country.trim();
    SUPPORTED_REGIONS
        .iter()
        .any(|region| region.country.eq_ignore_ascii_case(country))
}

/// 取受支持地区的定义。
pub fn region_for(country: &str) -> Option<&'static SupportedRegion> {
    let country = country.trim();
    SUPPORTED_REGIONS
        .iter()
        .find(|region| region.country.eq_ignore_ascii_case(country))
}

/// 该时区是否是可接受的默认时区。
///
/// 用于校验用户选定的时区是否属于某个受支持国家——防止「选日本却配纽约时区」
/// 这种配置错误流到系统设置里。
pub fn timezone_allowed(region: &SupportedRegion, tz: &str) -> bool {
    region
        .timezones
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(tz.trim()))
}

/// 校验「国家 + 时区」组合是否受支持；返回错误说明列表（空表示通过）。
pub fn validate(country: &str, tz: &str) -> Vec<String> {
    let mut errors = Vec::new();
    // 先快速判国家是否受支持，再取定义；两步都走同一份表，不会漂移。
    let region = if is_supported_country(country) {
        region_for(country)
    } else {
        None
    };
    let Some(region) = region else {
        let names: Vec<&str> = SUPPORTED_REGIONS.iter().map(|r| r.name).collect();
        errors.push(format!(
            "不支持的国家/地区代码「{country}」；仅支持 {}",
            names.join("、")
        ));
        return errors;
    };
    if !tz.trim().is_empty() && !timezone_allowed(region, tz) {
        errors.push(format!(
            "时区「{tz}」不属于{}；可选：{}",
            region.name,
            region.timezones.join("、")
        ));
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_three_countries_are_supported() {
        let names: Vec<&str> = SUPPORTED_REGIONS.iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["新加坡", "日本", "美国"]);
        let codes: Vec<&str> = SUPPORTED_REGIONS.iter().map(|r| r.country).collect();
        assert_eq!(codes, vec!["SG", "JP", "US"]);
    }

    #[test]
    fn country_lookup_is_case_insensitive_and_rejects_others() {
        assert!(is_supported_country("sg"));
        assert!(is_supported_country(" Jp "));
        assert!(is_supported_country("US"));
        for unsupported in ["CN", "GB", "DE", "HK", "", "ZZZ"] {
            assert!(!is_supported_country(unsupported), "{unsupported}");
        }
    }

    #[test]
    fn singapore_and_japan_have_exactly_one_timezone() {
        for code in ["SG", "JP"] {
            let region = region_for(code).unwrap();
            assert_eq!(region.timezones.len(), 1, "{code} 应只有一个时区");
        }
        assert_eq!(
            region_for("SG").unwrap().timezones[0],
            "Singapore Standard Time"
        );
        assert_eq!(
            region_for("JP").unwrap().timezones[0],
            "Tokyo Standard Time"
        );
    }

    #[test]
    fn us_offers_multiple_timezones_without_guessing() {
        let us = region_for("US").unwrap();
        assert!(us.timezones.len() >= 2, "多时区国家必须给出多个选项");
        assert!(us.timezones.contains(&"Pacific Standard Time"));
        assert!(us.timezones.contains(&"Eastern Standard Time"));
    }

    #[test]
    fn validate_rejects_unsupported_country_and_mismatched_timezone() {
        assert!(validate("SG", "Singapore Standard Time").is_empty());
        assert!(validate("JP", "").is_empty(), "空时区表示沿用推荐值");

        let errors = validate("CN", "China Standard Time");
        assert!(errors[0].contains("不支持"), "{errors:?}");
        assert!(errors[0].contains("新加坡"), "错误信息要列出可选项");

        // 选日本却配纽约时区：配置错误必须拦下，不能写进系统设置。
        let errors = validate("JP", "Eastern Standard Time");
        assert!(errors[0].contains("不属于日本"), "{errors:?}");

        // 美国：给出的任一常用时区都合法。
        assert!(validate("US", "Pacific Standard Time").is_empty());
        assert!(validate("US", "Eastern Standard Time").is_empty());
    }

    #[test]
    fn locales_match_regions() {
        assert_eq!(region_for("SG").unwrap().locale, "en-SG");
        assert_eq!(region_for("JP").unwrap().locale, "ja-JP");
        assert_eq!(region_for("US").unwrap().locale, "en-US");
    }
}
