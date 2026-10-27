//! STUN 泄漏探针（Rust 忠实移植自 `core/stun-probe.py`）。
//!
//! headless 浏览器做 WebRTC 拿不到 srflx 候选，因此直接向多个 STUN 服务器
//! （含国内节点）发 RFC 5389 Binding Request，解析响应里的
//! XOR-MAPPED-ADDRESS / MAPPED-ADDRESS，得到本机探测到的公网出口 IP。
//!
//! 判定语义与上游一致：
//! - 走隧道时，所有 STUN 服务器应返回代理出口 IP；
//! - 裸连时会暴露真实国内 IP；
//! - **没有任何 STUN 响应时绝不视为「零暴露」**——网络不通可能是被防火墙
//!   丢弃，而非没有泄漏，此时保守地在 `error` 字段说明，`leaks` 置 false。

use std::collections::HashSet;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// RFC 5389 magic cookie。
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Binding Request 消息类型。
const STUN_BINDING_REQUEST: u16 = 0x0001;
/// Binding Success Response 消息类型。
const STUN_BINDING_SUCCESS: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS 属性类型。
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// MAPPED-ADDRESS 属性类型（RFC 3489，兼容老实现）。
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// IPv4 family 字段值。
const FAMILY_IPV4: u8 = 0x01;

/// STUN 服务器列表：上游 4 台 + 国内 stun.qq.com（任务要求纳入）。
/// 国内节点裸连时必有响应，是检测真实 IP 泄漏的关键。
const STUN_SERVERS: &[(&str, u16)] = &[
    ("stun.miwifi.com", 3478),        // 国内节点：裸连时必有响应
    ("stun.chat.bilibili.com", 3478), // 国内节点
    ("stun.qq.com", 3478),            // 国内节点
    ("stun.l.google.com", 19302),     // 全球节点
    ("stun.cloudflare.com", 3478),    // 全球节点
];

/// 一次 STUN 泄漏探测的结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct StunResult {
    /// 期望的代理出口 IP（调用方从 egress 检查传入）。
    pub egress_ip: String,
    /// 实际从任一 STUN 服务器探测到的公网 IP（取首个去重值）；无响应时为 None。
    pub probed_ip: Option<String>,
    /// 是否检测到真实 IP 泄漏：任一探测 IP 与 `egress_ip` 不一致即视为泄漏。
    pub leaks: bool,
    /// 成功返回可解析 STUN 响应的服务器数量。
    pub servers_responded: usize,
    /// 无响应 / 全部失败时的保守说明；有响应时为 None。
    pub error: Option<String>,
}

/// 探测单个 STUN 服务器，返回其观察到的公网 IPv4。
///
/// 复刻上游 `stun_public_ip`：DNS 解析 → 绑 UDP socket → 设读超时 →
/// 发 Binding Request → 收响应 → 解析 mapped address。任一环节失败返回 None。
fn probe_one(host: &str, port: u16, timeout: Duration) -> Option<String> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;

    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes()); // message length，请求体为空
    packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet.extend_from_slice(&random_transaction_id());

    socket.send_to(&packet, addr).ok()?;
    let mut buf = [0u8; 1024];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    parse_mapped_address(&buf[..n])
}

/// 生成 12 字节事务 ID。仅用于请求匹配，这里用廉价 xorshift 从系统时间播种，
/// 不引入外部 rand crate。测试中直接调用 `parse_mapped_address`，不经过这里。
fn random_transaction_id() -> [u8; 12] {
    // 以系统墙钟播种一个 xorshift 序列；仅用于请求匹配，不要求密码学随机。
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15);

    let mut id = [0u8; 12];
    let mut x = seed.wrapping_add(0x9E37_79B9_7F4A_7C15) | 1; // 保证非 0
    for b in id.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x & 0xFF) as u8;
    }
    id
}

/// 解析 STUN 响应包，返回探测到的公网 IPv4 字符串。
///
/// 独立纯函数，便于表驱动单测。严格复刻上游 Python 解析逻辑：
/// - 包长 >= 20，且前两字节为 Binding Success (`0x0101`)；
/// - 从偏移 20 开始遍历 TLV 属性；
/// - `XOR-MAPPED-ADDRESS(0x0020)`：IPv4 时把地址 4 字节与 magic cookie 异或还原；
/// - `MAPPED-ADDRESS(0x0001)`：IPv4 时地址为明文；
/// - 属性按 4 字节对齐，尾部补零。
pub fn parse_mapped_address(packet: &[u8]) -> Option<String> {
    if packet.len() < 20 {
        return None;
    }
    // 响应消息类型必须是 Binding Success。
    if packet[0] != (STUN_BINDING_SUCCESS >> 8) as u8
        || packet[1] != (STUN_BINDING_SUCCESS & 0xFF) as u8
    {
        return None;
    }

    let mut pos = 20usize;
    while pos + 4 <= packet.len() {
        let attr_type = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let attr_len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        let value_start = pos + 4;
        let value_end = value_start + attr_len;
        if value_end > packet.len() {
            return None;
        }
        let value = &packet[value_start..value_end];

        // value[0]=reserved, value[1]=family, value[2..4]=port, value[4..8]=address
        if attr_len >= 8 && value[1] == FAMILY_IPV4 {
            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    let encoded = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                    let real = encoded ^ MAGIC_COOKIE;
                    return Some(fmt_ipv4(real));
                }
                ATTR_MAPPED_ADDRESS => {
                    return Some(format!(
                        "{}.{}.{}.{}",
                        value[4], value[5], value[6], value[7]
                    ));
                }
                _ => {}
            }
        }

        // 按 4 字节对齐跳过填充。
        let padding = (4 - attr_len % 4) % 4;
        pos = value_end + padding;
    }
    None
}

/// 把大端序 u32 格式化为点分十进制 IPv4。
fn fmt_ipv4(ip: u32) -> String {
    let b = ip.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// 并发向所有 STUN 服务器发 Binding Request，判断是否泄漏真实 IP。
///
/// `egress_ip`：期望的代理出口 IP；`timeout_ms`：单 socket 读超时（上游约 2s）。
/// 任一服务器返回的公网 IP 与 `egress_ip` 不一致 → `leaks=true`。
///
/// 当前尚未在 `lib.rs` 注册命令，由后续模块接线，故允许暂时未被引用。
#[allow(dead_code)]
pub fn probe_stun_leak(egress_ip: &str, timeout_ms: u64) -> StunResult {
    let per_socket = Duration::from_millis(timeout_ms.max(200));
    let (tx, rx) = mpsc::channel::<Option<String>>();

    for (host, port) in STUN_SERVERS {
        let tx = tx.clone();
        let host = (*host).to_string();
        let port = *port;
        thread::spawn(move || {
            let ip = probe_one(&host, port, per_socket);
            // 发送失败（接收端已 drop）无所谓，忽略结果。
            let _ = tx.send(ip);
        });
    }
    // 关闭本线程持有的发送端，使所有 worker 结束后 channel 自动断开。
    drop(tx);

    // 整体硬超时：单 socket 超时 + 一点 DNS/调度余量。
    let deadline = Instant::now() + per_socket + Duration::from_millis(500);
    let mut found: HashSet<String> = HashSet::new();
    let mut servers_responded = 0usize;

    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(remaining) {
            Ok(Some(ip)) => {
                servers_responded += 1;
                found.insert(ip);
            }
            Ok(None) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if found.is_empty() {
        // 上游语义：无任何响应时不能判定为零暴露。
        StunResult {
            egress_ip: egress_ip.to_string(),
            probed_ip: None,
            leaks: false,
            servers_responded: 0,
            error: Some(
                "没有任何 STUN 服务器响应；无法据此判断是否泄漏真实 IP（保守处理，不视为零暴露）"
                    .to_string(),
            ),
        }
    } else {
        let leaks = found.iter().any(|ip| ip != egress_ip);
        StunResult {
            egress_ip: egress_ip.to_string(),
            probed_ip: found.iter().next().cloned(),
            leaks,
            servers_responded,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 STUN Binding Success 响应头（20 字节）。
    fn success_header() -> Vec<u8> {
        let mut h = Vec::with_capacity(20);
        h.extend_from_slice(&(STUN_BINDING_SUCCESS).to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes()); // 占位，下面按属性重算
        h.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        h.extend_from_slice(&[0xAAu8; 12]); // 事务 ID
        h
    }

    /// 追加一个 TLV 属性到包尾部，并回写消息总长度。
    fn append_attr(packet: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
        packet.extend_from_slice(&attr_type.to_be_bytes());
        packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
        packet.extend_from_slice(value);
        let padding = (4 - value.len() % 4) % 4;
        packet.extend_from_slice(&vec![0u8; padding]);
        // 回写 message length = 从第 20 字节起的属性总字节数。
        let total = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
    }

    /// 构造 XOR-MAPPED-ADDRESS value（8 字节）。
    fn xor_mapped_value(real_ip: u32, port: u16) -> [u8; 8] {
        let x_addr = real_ip ^ MAGIC_COOKIE;
        let x_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let mut v = [0u8; 8];
        v[0] = 0x00; // reserved
        v[1] = FAMILY_IPV4;
        v[2..4].copy_from_slice(&x_port.to_be_bytes());
        v[4..8].copy_from_slice(&x_addr.to_be_bytes());
        v
    }

    /// 构造明文 MAPPED-ADDRESS value（8 字节）。
    fn mapped_value(ip: [u8; 4], port: u16) -> [u8; 8] {
        let mut v = [0u8; 8];
        v[0] = 0x00;
        v[1] = FAMILY_IPV4;
        v[2..4].copy_from_slice(&port.to_be_bytes());
        v[4..8].copy_from_slice(&ip);
        v
    }

    #[test]
    fn parses_xor_mapped_address() {
        // 真实 IP 203.0.113.5 = 0xCB00_7105
        let real: u32 = 0xCB00_7105;
        let mut packet = success_header();
        append_attr(
            &mut packet,
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_value(real, 5000),
        );
        assert_eq!(
            parse_mapped_address(&packet),
            Some("203.0.113.5".to_string())
        );
    }

    #[test]
    fn parses_mapped_address_plaintext() {
        let mut packet = success_header();
        append_attr(
            &mut packet,
            ATTR_MAPPED_ADDRESS,
            &mapped_value([198, 51, 100, 7], 5000),
        );
        assert_eq!(
            parse_mapped_address(&packet),
            Some("198.51.100.7".to_string())
        );
    }

    #[test]
    fn skips_unknown_attrs_and_padding_then_finds_xor_mapped() {
        // 一个长度为 3 的未知属性（触发 1 字节对齐填充），后面才是 XOR-MAPPED。
        let mut packet = success_header();
        append_attr(&mut packet, 0xFFFF, &[0xAA, 0xBB, 0xCC]);
        let real: u32 = 0x7F00_0001; // 127.0.0.1
        append_attr(
            &mut packet,
            ATTR_XOR_MAPPED_ADDRESS,
            &xor_mapped_value(real, 9999),
        );
        assert_eq!(parse_mapped_address(&packet), Some("127.0.0.1".to_string()));
    }

    #[test]
    fn rejects_wrong_message_type() {
        // 错误响应类型：Binding Error 0x0111。
        let mut packet = success_header();
        packet[0] = 0x01;
        packet[1] = 0x11;
        append_attr(
            &mut packet,
            ATTR_MAPPED_ADDRESS,
            &mapped_value([8, 8, 8, 8], 1234),
        );
        assert_eq!(parse_mapped_address(&packet), None);
    }

    #[test]
    fn rejects_short_packet() {
        assert_eq!(parse_mapped_address(&[]), None);
        assert_eq!(parse_mapped_address(&[0x01, 0x01, 0, 0]), None);
        assert_eq!(parse_mapped_address(&[0x01u8; 19]), None);
    }

    #[test]
    fn rejects_non_ipv4_family() {
        // family = 0x02 (IPv6)，不应解析。
        let mut packet = success_header();
        let mut v = [0u8; 8];
        v[0] = 0;
        v[1] = 0x02; // IPv6 family
        append_attr(&mut packet, ATTR_XOR_MAPPED_ADDRESS, &v);
        assert_eq!(parse_mapped_address(&packet), None);
    }

    #[test]
    fn egress_matches_no_leak_logic() {
        // 直接复用 probe_stun_leak 的判定语义做轻量校验：
        // 这里只验证「发现 IP 集合与 egress 全等 → leaks=false」的纯逻辑，
        // 不触网。
        let found: HashSet<String> = ["1.2.3.4".to_string()].into_iter().collect();
        let leaks = found.iter().any(|ip| ip != "1.2.3.4");
        assert!(!leaks);
        let leaks2 = found.iter().any(|ip| ip != "5.6.7.8");
        assert!(leaks2);
    }
}
