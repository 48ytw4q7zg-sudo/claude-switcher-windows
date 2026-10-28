//! 用量统计：本地 ~/.claude/projects 日志扫描 + 官方 OAuth usage API（带 TTL 缓存）。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::credentials;
use crate::net;
use crate::paths;
use crate::store;

#[derive(Debug, Clone, Default, Serialize)]
pub struct TokenTotals {
    pub input_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

impl TokenTotals {
    fn add_usage(&mut self, usage: &Value) {
        let input = number_field(usage, "input_tokens");
        let cache_creation = number_field(usage, "cache_creation_input_tokens");
        let cache_read = number_field(usage, "cache_read_input_tokens");
        let output = number_field(usage, "output_tokens");
        self.input_tokens += input;
        self.cache_creation_input_tokens += cache_creation;
        self.cache_read_input_tokens += cache_read;
        self.output_tokens += output;
        self.total_tokens += input + cache_creation + output;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageWindow {
    pub label: String,
    pub totals: TokenTotals,
    pub message_count: u64,
    pub reset_at: Option<DateTime<Utc>>,
    pub used_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DailyUsage {
    pub date: String,
    pub totals: TokenTotals,
    pub message_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaudeUsageSnapshot {
    pub updated_at: DateTime<Utc>,
    pub scanned_files: usize,
    pub scanned_messages: u64,
    pub latest_message_at: Option<DateTime<Utc>>,
    pub session: UsageWindow,
    pub weekly: UsageWindow,
    pub today: UsageWindow,
    pub last_30_days: UsageWindow,
    pub daily: Vec<DailyUsage>,
    pub top_model: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct UsageRecord {
    timestamp: DateTime<Utc>,
    model: String,
    usage: Value,
}

/// OAuth 缓存：TTL 内直接返回缓存值，托盘每分钟刷新不再打满 OAuth 请求。
///
/// **`token_fp` 是必须的**：早期版本只看是否过期，不看 token。切号后
/// `apply_oauth_profile` 拿新账号的 token 去查，返回的却是旧账号的邮箱和套餐
/// （profile TTL 6 小时），5 小时/7 天额度也会错 90 秒——界面显示的是上一个
/// 账号的数据。缓存里放 token 指纹，指纹不符就不算命中。
/// 指纹只在进程内比较，不落盘，也不存 token 本身。
#[derive(Debug, Clone)]
struct CachedOauthValue {
    fetched_at: DateTime<Utc>,
    value: Value,
    token_fp: u64,
}

/// token 指纹（进程内比较用，不落盘、不存 token 本身）。
fn token_fingerprint(token: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    token.hash(&mut hasher);
    hasher.finish()
}

static OAUTH_USAGE_CACHE: OnceLock<Mutex<Option<CachedOauthValue>>> = OnceLock::new();
static OAUTH_PROFILE_CACHE: OnceLock<Mutex<Option<CachedOauthValue>>> = OnceLock::new();
/// OAuth usage TTL：90 秒（托盘 60s 刷新 + 弹窗 30s 刷新命中缓存，不叠加请求）。
const OAUTH_USAGE_TTL_SECS: i64 = 90;
const OAUTH_PROFILE_TTL_SECS: i64 = 6 * 3600;

/// 主动清空所有缓存：切号 / 新号登录完成 / 清除凭据后必须调用。
///
/// 只靠 token 指纹能防「显示别的账号」，但切号后 projects 目录也换了，
/// 本地用量统计（`LOCAL_USAGE_CACHE`，45 秒）同样是旧账号的。切号是低频操作，
/// 直接全清最稳妥，也最符合用户预期。
pub fn clear_caches() {
    // 三个缓存的 value 类型不同，逐个清（不能用同一个迭代器）。
    if let Ok(mut guard) = OAUTH_USAGE_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *guard = None;
    }
    if let Ok(mut guard) = OAUTH_PROFILE_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *guard = None;
    }
    if let Ok(mut guard) = LOCAL_USAGE_CACHE.get_or_init(|| Mutex::new(None)).lock() {
        *guard = None;
    }
}

fn number_field(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn string_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str()
}

fn collect_jsonl_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("读取 Claude 日志目录失败: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        // entry.file_type 用目录项自带信息，省掉每项一次 is_dir 系统调用；
        // 但它**不跟随链接**，符号链接/junction 目录会被误判为非目录而漏掉。
        // 遇到 reparse point 时回退到 metadata()（跟随链接）再判断。
        let is_dir = match entry.file_type() {
            Ok(kind) if kind.is_symlink() => {
                entry.path().metadata().map(|m| m.is_dir()).unwrap_or(false)
            }
            Ok(kind) => kind.is_dir(),
            Err(_) => false,
        };
        if is_dir {
            collect_jsonl_files(&entry.path(), files)?;
        } else if entry.path().extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
            files.push(entry.path());
        }
    }
    Ok(())
}

/// 本地日志聚合结果也做短 TTL 缓存：托盘每 60 秒、弹窗每 30 秒调用时，
/// 不需要反复把近 30 天的 jsonl 全部逐行读一遍。45 秒覆盖同一轮界面刷新，
/// 又足够快地看到新日志。文件级增量解析留作后续优化，当前不牺牲正确性。
const LOCAL_USAGE_TTL: StdDuration = StdDuration::from_secs(45);
static LOCAL_USAGE_CACHE: OnceLock<Mutex<Option<(std::time::Instant, ClaudeUsageSnapshot)>>> =
    OnceLock::new();

pub fn claude_usage_snapshot() -> Result<ClaudeUsageSnapshot, String> {
    let cache = LOCAL_USAGE_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((at, snapshot)) = guard.as_ref() {
            if at.elapsed() < LOCAL_USAGE_TTL {
                return Ok(snapshot.clone());
            }
        }
    }

    let snapshot = claude_usage_snapshot_uncached()?;
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((std::time::Instant::now(), snapshot.clone()));
    }
    Ok(snapshot)
}

/// 跳过子代理日志与探针文件；Windows 路径分隔符是 `\`，
/// 同时匹配 `/subagents/` 与 `\subagents\`（原版只匹配 `/`，Windows 全漏）。
fn should_scan_usage_file(path: &Path, cutoff: DateTime<Utc>) -> bool {
    let path_text = path.to_string_lossy().replace('\\', "/");
    if path_text.contains("/subagents/") || path_text.contains("CodexBar-ClaudeProbe") {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return true;
    };
    let modified: DateTime<Utc> = modified.into();
    modified >= cutoff
}

fn usage_window(
    label: &str,
    totals: TokenTotals,
    message_count: u64,
    reset_at: Option<DateTime<Utc>>,
) -> UsageWindow {
    UsageWindow {
        label: label.to_string(),
        totals,
        message_count,
        reset_at,
        used_percent: None,
    }
}

fn parse_oauth_reset(value: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = value?.trim();
    if raw.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn apply_oauth_window(window: &mut UsageWindow, value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(utilization) = value.get("utilization").and_then(|v| v.as_f64()) else {
        return false;
    };
    window.used_percent = Some(utilization.clamp(0.0, 100.0));
    window.reset_at = parse_oauth_reset(value.get("resets_at").and_then(|v| v.as_str()));
    true
}

fn oauth_access_token_from_raw(raw: &str) -> Result<String, String> {
    let parsed: Value =
        serde_json::from_str(raw).map_err(|e| format!("OAuth 凭据 JSON 解析失败: {e}"))?;
    let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
    string_field(oauth, &["accessToken"])
        .or_else(|| string_field(oauth, &["access_token"]))
        .map(ToOwned::to_owned)
        .ok_or_else(|| "OAuth 凭据中没有 accessToken".to_string())
}

fn cached_oauth_endpoint(
    cache: &'static Mutex<Option<CachedOauthValue>>,
    path: &str,
    access_token: &str,
    ttl_secs: i64,
) -> Result<Value, String> {
    let token_fp = token_fingerprint(access_token);
    // 快路径：TTL 内**且 token 指纹匹配**才返回缓存。
    // 只判 TTL 会切号后仍返回上一个账号的数据（见 CachedOauthValue 注释）。
    {
        // 锁中毒时取内部数据继续（与本文件 INFLIGHT 的策略一致）：
        // expect() 会在任一线程 panic 后让后续所有用量查询连锁 panic。
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = guard.as_ref() {
            if cached.token_fp == token_fp
                && Utc::now() - cached.fetched_at < Duration::seconds(ttl_secs)
            {
                return Ok(cached.value.clone());
            }
        }
    }

    // 慢路径：需要真的发请求。用 in-flight 标记把并发调用合并成一次——
    // 托盘（60s）与弹窗（30s）会在缓存过期的同一刻同时进来，不合并就是两次请求。
    let mut inflight = INFLIGHT
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(holder) = inflight.get(path) {
        if *holder {
            // 已有线程在请求：等它完成后读缓存，最多等 3 秒。
            drop(inflight);
            for _ in 0..30 {
                std::thread::sleep(StdDuration::from_millis(100));
                if let Ok(guard) = cache.lock() {
                    if let Some(cached) = guard.as_ref() {
                        // 同样要核对 token 指纹，否则等来的是别的账号的数据。
                        if cached.token_fp == token_fp
                            && Utc::now() - cached.fetched_at < Duration::seconds(ttl_secs)
                        {
                            return Ok(cached.value.clone());
                        }
                    }
                }
            }
            // 等待超时也没拿到新值：落到下面的真实请求（不再无限等）。
            inflight = INFLIGHT
                .get_or_init(|| Mutex::new(BTreeMap::new()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());
        }
    }
    inflight.insert(path.to_string(), true);
    drop(inflight);

    let result = net::claude_oauth_api(path, access_token);

    // 无论成败都清掉 in-flight 标记，避免后续请求永久等待。
    if let Ok(mut inflight) = INFLIGHT.get_or_init(|| Mutex::new(BTreeMap::new())).lock() {
        inflight.insert(path.to_string(), false);
    }

    match result {
        Ok(value) => {
            if let Ok(mut guard) = cache.lock() {
                *guard = Some(CachedOauthValue {
                    fetched_at: Utc::now(),
                    value: value.clone(),
                    token_fp,
                });
            }
            Ok(value)
        }
        Err(error) => {
            // 请求失败时放宽到 5×TTL 的陈旧缓存，避免完全无数据。
            // 但**必须核对 token 指纹**：否则断网期间切号，会把上一个账号的
            // 陈旧数据当成当前账号的返回。
            let stale = cache
                .lock()
                .ok()
                .and_then(|guard| guard.clone())
                .filter(|cached| {
                    cached.token_fp == token_fp
                        && Utc::now() - cached.fetched_at < Duration::seconds(ttl_secs * 5)
                })
                .map(|cached| cached.value);
            stale.ok_or(error)
        }
    }
}

/// in-flight 标记：某个 endpoint 是否正在请求中（把并发调用合并成一次）。
static INFLIGHT: OnceLock<Mutex<BTreeMap<String, bool>>> = OnceLock::new();

pub fn cached_oauth_profile(access_token: &str) -> Result<Value, String> {
    cached_oauth_endpoint(
        OAUTH_PROFILE_CACHE.get_or_init(|| Mutex::new(None)),
        "/api/oauth/profile",
        access_token,
        OAUTH_PROFILE_TTL_SECS,
    )
}

fn apply_oauth_usage(snapshot: &mut ClaudeUsageSnapshot) -> Result<(), String> {
    let Some(raw) = credentials::read_password()? else {
        return Err("没有 Claude OAuth 凭据".to_string());
    };
    let access_token = oauth_access_token_from_raw(&raw)?;
    let value = cached_oauth_endpoint(
        OAUTH_USAGE_CACHE.get_or_init(|| Mutex::new(None)),
        "/api/oauth/usage",
        &access_token,
        OAUTH_USAGE_TTL_SECS,
    )?;

    let session_ok = apply_oauth_window(&mut snapshot.session, value.get("five_hour"));
    let weekly_ok = apply_oauth_window(&mut snapshot.weekly, value.get("seven_day"));
    if !session_ok && !weekly_ok {
        return Err("Claude OAuth usage 响应缺少 five_hour/seven_day utilization".to_string());
    }
    Ok(())
}

fn model_from_message(message: &Value) -> Option<String> {
    let model = string_field(message, &["model"])?;
    let clean = model.trim();
    if clean.is_empty() || clean == "<synthetic>" {
        None
    } else {
        Some(clean.to_string())
    }
}

fn usage_dedupe_key(path: &Path, value: &Value, message: &Value, fallback: u64) -> String {
    let message_id = string_field(message, &["id"])
        .or_else(|| string_field(value, &["messageId"]))
        .or_else(|| string_field(value, &["message_id"]))
        .or_else(|| string_field(value, &["uuid"]));
    let request_id = string_field(value, &["requestId"])
        .or_else(|| string_field(value, &["request_id"]))
        .or_else(|| string_field(message, &["requestId"]))
        .or_else(|| string_field(message, &["request_id"]));
    match (message_id, request_id) {
        (Some(message_id), Some(request_id)) => format!("{message_id}:{request_id}"),
        (Some(message_id), None) => message_id.to_string(),
        (None, Some(request_id)) => request_id.to_string(),
        (None, None) => format!("{}:{fallback}", path.to_string_lossy()),
    }
}

fn usage_total_for_dedupe(usage: &Value) -> u64 {
    number_field(usage, "input_tokens")
        + number_field(usage, "cache_creation_input_tokens")
        + number_field(usage, "cache_read_input_tokens")
        + number_field(usage, "output_tokens")
}

fn estimate_reset_at(earliest: Option<DateTime<Utc>>, window: Duration) -> Option<DateTime<Utc>> {
    earliest.map(|value| value + window)
}

fn update_earliest(target: &mut Option<DateTime<Utc>>, timestamp: DateTime<Utc>) {
    if target.map(|current| timestamp < current).unwrap_or(true) {
        *target = Some(timestamp);
    }
}

fn update_latest(target: &mut Option<DateTime<Utc>>, timestamp: DateTime<Utc>) {
    if target.map(|current| timestamp > current).unwrap_or(true) {
        *target = Some(timestamp);
    }
}

fn claude_usage_snapshot_uncached() -> Result<ClaudeUsageSnapshot, String> {
    let now = Utc::now();
    let session_window = Duration::hours(5);
    let weekly_window = Duration::days(7);
    let month_window = Duration::days(30);
    let session_cutoff = now - session_window;
    let weekly_cutoff = now - weekly_window;
    let month_cutoff = now - month_window;
    let today = now.date_naive();

    let mut files = Vec::new();
    collect_jsonl_files(&paths::claude_projects_dir()?, &mut files)?;
    files.retain(|path| should_scan_usage_file(path, month_cutoff));

    let mut scanned_messages = 0;
    let mut fallback_usage_key = 0u64;
    let mut usage_records: BTreeMap<String, UsageRecord> = BTreeMap::new();
    let mut warnings = Vec::new();

    for path in &files {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) => {
                warnings.push(format!("跳过无法读取的日志文件: {e}"));
                continue;
            }
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let Some(timestamp_raw) = string_field(&value, &["timestamp"]) else {
                continue;
            };
            let Ok(timestamp) = DateTime::parse_from_rfc3339(timestamp_raw) else {
                continue;
            };
            let timestamp = timestamp.with_timezone(&Utc);
            if timestamp < month_cutoff {
                continue;
            }

            let message = value.get("message").unwrap_or(&value);
            let entry_type = string_field(&value, &["type"])
                .or_else(|| string_field(message, &["type"]))
                .unwrap_or("");
            if entry_type != "assistant" {
                continue;
            }
            if value
                .get("isSidechain")
                .and_then(|item| item.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(model) = model_from_message(message) else {
                continue;
            };
            let Some(usage) = message.get("usage").or_else(|| value.get("usage")) else {
                continue;
            };
            if !usage.is_object() {
                continue;
            }

            scanned_messages += 1;
            fallback_usage_key += 1;
            let key = usage_dedupe_key(path, &value, message, fallback_usage_key);
            let should_replace = usage_records
                .get(&key)
                .map(|current| {
                    timestamp >= current.timestamp
                        || usage_total_for_dedupe(usage) > usage_total_for_dedupe(&current.usage)
                })
                .unwrap_or(true);
            if should_replace {
                usage_records.insert(
                    key,
                    UsageRecord {
                        timestamp,
                        model,
                        usage: usage.clone(),
                    },
                );
            }
        }
    }

    let mut session_totals = TokenTotals::default();
    let mut weekly_totals = TokenTotals::default();
    let mut today_totals = TokenTotals::default();
    let mut month_totals = TokenTotals::default();
    let mut session_messages = 0;
    let mut weekly_messages = 0;
    let mut today_messages = 0;
    let mut month_messages = 0;
    let mut latest_message_at: Option<DateTime<Utc>> = None;
    let mut latest_session: Option<DateTime<Utc>> = None;
    let mut latest_weekly: Option<DateTime<Utc>> = None;
    let mut earliest_today: Option<DateTime<Utc>> = None;
    let mut earliest_month: Option<DateTime<Utc>> = None;
    let mut daily: BTreeMap<String, (TokenTotals, u64)> = BTreeMap::new();
    let mut model_counts: BTreeMap<String, u64> = BTreeMap::new();

    for record in usage_records.values() {
        let timestamp = record.timestamp;
        let usage = &record.usage;
        update_latest(&mut latest_message_at, timestamp);
        *model_counts.entry(record.model.clone()).or_default() += 1;

        month_totals.add_usage(usage);
        month_messages += 1;
        update_earliest(&mut earliest_month, timestamp);
        add_daily_usage(&mut daily, timestamp, usage);

        if timestamp >= weekly_cutoff {
            weekly_totals.add_usage(usage);
            weekly_messages += 1;
            update_latest(&mut latest_weekly, timestamp);
        }
        if timestamp >= session_cutoff {
            session_totals.add_usage(usage);
            session_messages += 1;
            update_latest(&mut latest_session, timestamp);
        }
        if timestamp.date_naive() == today {
            today_totals.add_usage(usage);
            today_messages += 1;
            update_earliest(&mut earliest_today, timestamp);
        }
    }

    let seen_days: BTreeSet<String> = daily.keys().cloned().collect();
    let mut daily_rows = Vec::new();
    for offset in (0..30).rev() {
        let date = (today - Duration::days(offset)).to_string();
        let (totals, message_count) = daily.remove(&date).unwrap_or_default();
        daily_rows.push(DailyUsage {
            date,
            totals,
            message_count,
        });
    }
    if seen_days.is_empty() {
        warnings.push("没有从 ~/.claude/projects 读取到最近 30 天的 usage 记录".to_string());
    }

    let top_model = model_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(model, _)| model);

    let mut snapshot = ClaudeUsageSnapshot {
        updated_at: now,
        scanned_files: files.len(),
        scanned_messages,
        latest_message_at,
        session: usage_window(
            "近 5 小时",
            session_totals,
            session_messages,
            estimate_reset_at(latest_session, session_window),
        ),
        weekly: usage_window(
            "近 7 天",
            weekly_totals,
            weekly_messages,
            estimate_reset_at(latest_weekly, weekly_window),
        ),
        today: usage_window(
            "今天",
            today_totals,
            today_messages,
            estimate_reset_at(earliest_today, Duration::days(1)),
        ),
        last_30_days: usage_window(
            "近 30 天",
            month_totals,
            month_messages,
            estimate_reset_at(earliest_month, month_window),
        ),
        daily: daily_rows,
        top_model,
        warnings,
    };
    if let Err(error) = apply_oauth_usage(&mut snapshot) {
        snapshot.warnings.push(format!(
            "官方 Claude OAuth usage 读取失败，已回退本地日志估算: {error}"
        ));
    }
    Ok(snapshot)
}

fn add_daily_usage(
    daily: &mut BTreeMap<String, (TokenTotals, u64)>,
    timestamp: DateTime<Utc>,
    usage: &Value,
) {
    let key = timestamp.date_naive().to_string();
    let (totals, count) = daily.entry(key).or_default();
    totals.add_usage(usage);
    *count += 1;
}

pub fn hash_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    format!("{:x}", digest)[..12].to_string()
}

/// 提取账号元信息（email / uuid / 订阅等）。
pub fn extract_meta(
    claude_json: Option<&Value>,
    keychain_password: Option<&str>,
) -> store::ProfileMeta {
    let mut meta = store::ProfileMeta::default();

    if let Some(cfg) = claude_json {
        meta.email = string_field(cfg, &["oauthAccount", "email"]).map(ToOwned::to_owned);
        meta.account_uuid =
            string_field(cfg, &["oauthAccount", "accountUuid"]).map(ToOwned::to_owned);
        meta.organization_uuid =
            string_field(cfg, &["oauthAccount", "organizationUuid"]).map(ToOwned::to_owned);
        meta.organization_name =
            string_field(cfg, &["oauthAccount", "organizationName"]).map(ToOwned::to_owned);
        meta.has_oauth_account = cfg.get("oauthAccount").is_some();
        meta.user_id_hash = string_field(cfg, &["userID"]).map(hash_short);
    }

    if let Some(raw) = keychain_password {
        meta.has_keychain_credentials = true;
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
            meta.has_oauth_account = true;
            if meta.email.is_none() {
                meta.email = string_field(oauth, &["email", "accountEmail", "username"])
                    .map(ToOwned::to_owned);
            }
            meta.has_trusted_device_token = oauth.get("trustedDeviceToken").is_some();
            meta.subscription_type =
                string_field(oauth, &["subscriptionType"]).map(ToOwned::to_owned);
            meta.rate_limit_tier = string_field(oauth, &["rateLimitTier"]).map(ToOwned::to_owned);
        }
    }

    meta
}

/// 用官方 OAuth profile 接口补齐 / 修正账号元信息（6 小时缓存）。
pub fn apply_oauth_profile(
    meta: &mut store::ProfileMeta,
    keychain_password: Option<&str>,
) -> Result<(), String> {
    let Some(raw) = keychain_password else {
        return Ok(());
    };
    let access_token = oauth_access_token_from_raw(raw)?;
    let value = cached_oauth_profile(&access_token)?;
    if let Some(account) = value.get("account") {
        meta.email = string_field(account, &["email"])
            .map(ToOwned::to_owned)
            .or(meta.email.take());
        meta.account_uuid = string_field(account, &["uuid"])
            .map(ToOwned::to_owned)
            .or(meta.account_uuid.take());
        if account
            .get("has_claude_max")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            meta.subscription_type = Some("max".to_string());
        } else if account
            .get("has_claude_pro")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            meta.subscription_type = Some("pro".to_string());
        }
    }
    if let Some(organization) = value.get("organization") {
        meta.organization_uuid = string_field(organization, &["uuid"])
            .map(ToOwned::to_owned)
            .or(meta.organization_uuid.take());
        meta.organization_name = string_field(organization, &["name"])
            .map(ToOwned::to_owned)
            .or(meta.organization_name.take());
        meta.rate_limit_tier = string_field(organization, &["rate_limit_tier"])
            .map(ToOwned::to_owned)
            .or(meta.rate_limit_tier.take());
    }
    meta.has_oauth_account = true;
    Ok(())
}

/// P2-1：阈值提醒里推荐切换的账号。
#[derive(Debug, Serialize)]
pub struct RecommendedAccount {
    pub id: String,
    pub name: String,
    pub last_used_percent: Option<f64>,
}

/// P2-1：阈值提醒结果。
#[derive(Debug, Serialize)]
pub struct QuotaReminder {
    pub enabled: bool,
    pub threshold: u8,
    /// 当前账号 5 小时用量百分比。
    pub current_percent: Option<f64>,
    /// 达阈值时，缓存里余量最多的账号（供「一键切换」）；未达阈值为 None。
    pub recommended: Option<RecommendedAccount>,
}

/// 把当前账号的 5 小时用量百分比缓存到其 profile（仅在变化时写盘）。
/// best-effort：失败不影响主流程。
fn record_current_usage_percent(percent: f64) {
    let Ok(mut store_data) = store::load_store() else {
        return;
    };
    let Some(current_id) = store_data.current_profile_id.clone() else {
        return;
    };
    let Some(profile) = store_data.profiles.iter_mut().find(|p| p.id == current_id) else {
        return;
    };
    // 保留一位小数，避免微小波动反复写盘。
    let rounded = (percent * 10.0).round() / 10.0;
    if profile.last_used_percent == Some(rounded) {
        return;
    }
    profile.last_used_percent = Some(rounded);
    profile.updated_at = Utc::now();
    let _ = store::save_store(&store_data);
}

/// 纯函数：在候选（id, name, 缓存百分比）中选余量最多（百分比最小）的账号。
fn pick_most_remaining<'a>(
    candidates: &[(&'a str, &'a str, f64)],
) -> Option<(&'a str, &'a str, f64)> {
    candidates
        .iter()
        .copied()
        .min_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
}

/// P2-1：阈值提醒（阻塞，调用方走 blocking）。
///
/// 只做提醒 + 推荐，**不做后台自动换号**：其他账号用量会过时、后台刷新令牌风险高，
/// 真正切换由用户点「一键切换」触发。
pub fn quota_reminder_blocking() -> Result<QuotaReminder, String> {
    let config = crate::appconfig::load();
    let threshold = config.quota_reminder_threshold;
    if !config.quota_reminder_enabled {
        return Ok(QuotaReminder {
            enabled: false,
            threshold,
            current_percent: None,
            recommended: None,
        });
    }

    let snapshot = claude_usage_snapshot()?;
    let current_percent = snapshot.session.used_percent;
    if let Some(p) = current_percent {
        record_current_usage_percent(p);
    }

    let crossed = current_percent
        .map(|p| p >= f64::from(threshold))
        .unwrap_or(false);

    let recommended = if crossed {
        let store_data = store::load_store()?;
        let current_id = store_data.current_profile_id;
        let candidates: Vec<(&str, &str, f64)> = store_data
            .profiles
            .iter()
            .filter(|p| Some(p.id.as_str()) != current_id.as_deref())
            .filter_map(|p| {
                p.last_used_percent
                    .map(|pct| (p.id.as_str(), p.name.as_str(), pct))
            })
            .collect();
        pick_most_remaining(&candidates).map(|(id, name, pct)| RecommendedAccount {
            id: id.to_string(),
            name: name.to_string(),
            last_used_percent: Some(pct),
        })
    } else {
        None
    };

    Ok(QuotaReminder {
        enabled: true,
        threshold,
        current_percent,
        recommended,
    })
}

pub fn compact_token_count(value: u64) -> String {
    if value >= 1_000_000_000 {
        let scaled = value as f64 / 1_000_000_000.0;
        if value >= 10_000_000_000 {
            format!("{scaled:.0}B")
        } else {
            format!("{scaled:.1}B")
        }
    } else if value >= 1_000_000 {
        let scaled = value as f64 / 1_000_000.0;
        if value >= 10_000_000 {
            format!("{scaled:.0}M")
        } else {
            format!("{scaled:.1}M")
        }
    } else if value >= 1_000 {
        let scaled = value as f64 / 1_000.0;
        if value >= 10_000 {
            format!("{scaled:.0}K")
        } else {
            format!("{scaled:.1}K")
        }
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_scan_usage_file_matches_windows_path_subagents() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subagents");
        std::fs::create_dir_all(&sub).unwrap();
        let blocked = sub.join("session.jsonl");
        std::fs::write(&blocked, "").unwrap();
        let normal = dir.path().join("session.jsonl");
        std::fs::write(&normal, "").unwrap();
        assert!(!should_scan_usage_file(
            &blocked,
            Utc::now() - Duration::days(1)
        ));
        assert!(should_scan_usage_file(
            &normal,
            Utc::now() - Duration::days(1)
        ));
    }

    #[test]
    fn compact_token_count_formatting() {
        assert_eq!(compact_token_count(0), "0");
        assert_eq!(compact_token_count(1_500), "1.5K");
        assert_eq!(compact_token_count(15_000), "15K");
        assert_eq!(compact_token_count(2_500_000), "2.5M");
        assert_eq!(compact_token_count(3_200_000_000), "3.2B");
    }

    #[test]
    fn oauth_access_token_parses_both_shapes() {
        let nested = serde_json::json!({
            "claudeAiOauth": { "accessToken": "tok-1", "expiresAt": 1 }
        })
        .to_string();
        assert_eq!(oauth_access_token_from_raw(&nested).unwrap(), "tok-1");
        let flat = serde_json::json!({ "access_token": "tok-2" }).to_string();
        assert_eq!(oauth_access_token_from_raw(&flat).unwrap(), "tok-2");
    }

    #[test]
    fn pick_most_remaining_returns_lowest_percent() {
        let candidates = [("a", "A", 80.0), ("b", "B", 40.0), ("c", "C", 60.0)];
        assert_eq!(pick_most_remaining(&candidates), Some(("b", "B", 40.0)));
        assert_eq!(pick_most_remaining(&[]), None);
    }

    #[test]
    fn extract_meta_reads_oauth_account() {
        let claude_json = serde_json::json!({
            "userID": "u1",
            "oauthAccount": { "email": "a@example.com", "accountUuid": "uuid-1" }
        });
        let meta = extract_meta(Some(&claude_json), None);
        assert_eq!(meta.email.as_deref(), Some("a@example.com"));
        assert_eq!(meta.account_uuid.as_deref(), Some("uuid-1"));
        assert_eq!(meta.user_id_hash.as_deref().map(|s| s.len()), Some(12));
    }
}
