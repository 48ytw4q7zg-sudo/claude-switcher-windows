//! 令牌状态列（F-3）：纯本地计算，**不发任何网络请求**。
//!
//! 从 keychain blob（JSON 字符串）里的 `claudeAiOauth.expiresAt`（毫秒）判断访问令牌
//! 处于有效 / 即将过期 / 已过期 / 未知；同时检查是否存在刷新令牌，供前端区分
//! 「访问令牌已过期，使用时自动续期」与「无刷新令牌，需重新登录」两种文案。

use serde::Serialize;

/// 即将过期窗口：距过期不足 10 分钟即标记为 expiring。
const EXPIRING_WINDOW_MS: u64 = 10 * 60 * 1000;

/// 单个账号的令牌状态（随 ProfileSummary 序列化给前端）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenStatus {
    /// `valid`（有效）｜`expiring`（10 分钟内过期）｜`expired`（已过期）｜`unknown`（无法解析）。
    pub state: &'static str,
    /// 是否存在非空刷新令牌；决定过期后的提示与处理方式。
    pub has_refresh_token: bool,
    /// 访问令牌过期时间（Unix 毫秒），解析不到为 None。
    pub expires_at_ms: Option<u64>,
}

/// 当前 Unix 毫秒时间戳（SystemTime 不可用时回退 0）。
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

/// 纯函数：以给定的 `now_ms` 计算令牌状态，便于测试注入时间。
pub fn evaluate_token_status(blob: &str, now_ms: u64) -> TokenStatus {
    let parsed = match serde_json::from_str::<serde_json::Value>(blob) {
        Ok(value) => value,
        Err(_) => {
            return TokenStatus {
                state: "unknown",
                has_refresh_token: false,
                expires_at_ms: None,
            }
        }
    };
    // 兼容嵌套（claudeAiOauth 键）与扁平（根即 oauth）两种形态。
    let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
    let expires_at_ms = oauth.get("expiresAt").and_then(|v| v.as_u64());
    let has_refresh_token = oauth
        .get("refreshToken")
        .and_then(|v| v.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let Some(expires_at) = expires_at_ms else {
        return TokenStatus {
            state: "unknown",
            has_refresh_token,
            expires_at_ms: None,
        };
    };

    let state = if now_ms >= expires_at {
        "expired"
    } else if expires_at.saturating_sub(now_ms) <= EXPIRING_WINDOW_MS {
        "expiring"
    } else {
        "valid"
    };
    TokenStatus {
        state,
        has_refresh_token,
        expires_at_ms: Some(expires_at),
    }
}

/// 用当前系统时间计算令牌状态。
pub fn token_status_from_blob(blob: &str) -> TokenStatus {
    evaluate_token_status(blob, now_unix_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;

    fn blob_with(expires_at: i64, refresh: bool) -> String {
        let refresh_json = if refresh {
            ",\"refreshToken\":\"r-token\""
        } else {
            ",\"refreshToken\":\"\""
        };
        format!("{{\"claudeAiOauth\":{{\"expiresAt\":{expires_at}{refresh_json}}}}}")
    }

    #[test]
    fn valid_when_expiry_is_far_out() {
        let now = 1_000_000;
        let s = evaluate_token_status(&blob_with(now as i64 + 60 * MIN, true), now);
        assert_eq!(s.state, "valid");
        assert!(s.has_refresh_token);
    }

    #[test]
    fn expiring_within_ten_minutes() {
        let now = 1_000_000;
        let s = evaluate_token_status(&blob_with(now as i64 + 5 * MIN, true), now);
        assert_eq!(s.state, "expiring");
        // 恰好 10 分钟边界也算 expiring。
        let boundary = evaluate_token_status(&blob_with(now as i64 + 10 * MIN, true), now);
        assert_eq!(boundary.state, "expiring");
    }

    #[test]
    fn expired_when_now_past_expiry() {
        let now = 1_000_000;
        let s = evaluate_token_status(&blob_with(now as i64 - MIN, false), now);
        assert_eq!(s.state, "expired");
        assert!(!s.has_refresh_token);
    }

    #[test]
    fn unknown_when_expires_at_missing_or_blob_invalid() {
        let now = 1_000_000;
        let no_expiry = "{\"claudeAiOauth\":{\"accessToken\":\"a\"}}";
        assert_eq!(evaluate_token_status(no_expiry, now).state, "unknown");
        assert_eq!(evaluate_token_status("not json", now).state, "unknown");
    }

    #[test]
    fn supports_flat_blob_shape() {
        let now = 1_000_000;
        let flat = format!("{{\"expiresAt\":{}}}", now as i64 + 60 * MIN);
        assert_eq!(evaluate_token_status(&flat, now).state, "valid");
    }
}
