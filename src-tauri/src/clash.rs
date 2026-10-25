//! Clash 状态查询与节点切换。

use std::thread;
use std::time::Duration as StdDuration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::net;

#[derive(Debug, Clone, Serialize)]
pub struct ClashStatus {
    pub available: bool,
    pub controller: String,
    pub group: String,
    pub group_type: Option<String>,
    pub now: Option<String>,
    pub nodes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClashSwitchResult {
    pub group: String,
    pub node: String,
    pub previous: Option<String>,
    pub verified: bool,
}

fn string_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str()
}

pub fn read_clash_group(group: &str) -> Result<Value, String> {
    net::clash_api("GET", &net::clash_group_path(group), None)
}

fn read_clash_proxy(node: &str) -> Result<Value, String> {
    net::clash_api("GET", &net::clash_proxy_path(node), None)
}

pub fn assert_clash_node_ready(group: &str, node: &str) -> Result<(), String> {
    thread::sleep(StdDuration::from_millis(250));
    let group_state = read_clash_group(group)?;
    let now = string_field(&group_state, &["now"]);
    if now != Some(node) {
        return Err(format!(
            "Auto-Claude 没有切到「{node}」，当前仍是「{}」。已停止准备新号。",
            now.unwrap_or("未读取")
        ));
    }

    let node_state = read_clash_proxy(node)?;
    if !node_state
        .get("alive")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return Err(format!(
            "节点「{node}」当前不可用（Clash alive=false），已停止准备新号。"
        ));
    }

    let delay_path = format!(
        "{}/delay?timeout=5000&url=https%3A%2F%2Fapi.anthropic.com",
        net::clash_proxy_path(node)
    );
    let delay = net::clash_api("GET", &delay_path, None)?;
    let delay_ms = delay.get("delay").and_then(|value| value.as_u64());
    if delay_ms.unwrap_or(0) == 0 {
        return Err(format!(
            "节点「{node}」到 api.anthropic.com 延迟测试失败，已停止准备新号。"
        ));
    }
    Ok(())
}

pub fn clash_status_for_group(group: &str) -> ClashStatus {
    let runtime = net::detect_clash_runtime_config();
    match read_clash_group(group) {
        Ok(value) => ClashStatus {
            available: true,
            controller: runtime.controller,
            group: group.to_string(),
            group_type: string_field(&value, &["type"]).map(ToOwned::to_owned),
            now: string_field(&value, &["now"]).map(ToOwned::to_owned),
            nodes: value
                .get("all")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            error: None,
        },
        Err(error) => ClashStatus {
            available: false,
            controller: runtime.controller,
            group: group.to_string(),
            group_type: None,
            now: None,
            nodes: Vec::new(),
            error: Some(error),
        },
    }
}

pub fn switch_clash_node_internal(group: &str, node: &str) -> Result<ClashSwitchResult, String> {
    let before = read_clash_group(group)?;
    let previous = string_field(&before, &["now"]).map(ToOwned::to_owned);
    let nodes: Vec<String> = before
        .get("all")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !nodes.iter().any(|item| item == node) {
        return Err(format!("节点「{node}」不在「{group}」组里"));
    }

    net::clash_api(
        "PUT",
        &net::clash_group_path(group),
        Some(json!({ "name": node })),
    )?;
    let after = read_clash_group(group)?;
    let now = string_field(&after, &["now"]).map(ToOwned::to_owned);
    Ok(ClashSwitchResult {
        group: group.to_string(),
        node: node.to_string(),
        previous,
        verified: now.as_deref() == Some(node),
    })
}
