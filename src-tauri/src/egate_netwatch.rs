//! 直连泄露观察（融合 ClaudeGuard `src/netwatch.rs`，v3.12）。
//!
//! 与 [`crate::egate_access`] 的分工：那里根据**配置**推断「应该走哪条路」，这里回答
//! 更实际的问题——被守护的应用此刻**到底连到哪去了**。配置看着正常、出口校验也通过，
//! 但某个进程绕过系统代理直连公网时，应用本体已经在用真实 IP 说话。
//!
//! 判定（仅 IPv4 TCP）：
//! - 对端是回环且端口等于代理端口 → `Proxy`（正常）；
//! - 对端是回环/私网/链路本地/fake-IP 段 → `Local`（正常，不算泄露）；
//! - 其余 → `Public`（直连，硬证据）。
//!
//! 已知边界（写在这里免得后来者当 bug 修）：
//! 1. **只看 TCP**：UDP/QUIC 没有可靠的连接态，看不见；
//! 2. **只看被守护进程本身**，不看子进程（WebView2 渲染进程会自己连微软域名，
//!    算进来全是噪声）。代价是子进程里的泄露漏检。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use serde::Serialize;

/// 对端分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    /// 走系统代理端口（正常）。
    Proxy,
    /// 本地/私网通信（正常）。
    Local,
    /// 直连公网（泄露证据）。
    Public,
}

/// 一条 TCP 连接（只保留判定需要的字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    pub pid: u32,
    pub remote: Ipv4Addr,
    pub port: u16,
}

/// 单条直连记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeakConn {
    pub pid: u32,
    pub agent: String,
    pub remote: String,
    pub port: u16,
}

/// 单轮观察结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeakReport {
    /// 本次是否具备判定条件（只有系统代理模式才判）。
    pub applicable: bool,
    /// 判定时的接入方式：system_proxy / tun / uncovered / unknown。
    pub mode: String,
    /// 被守护进程的 ESTABLISHED 连接总数。
    pub agent_conns: usize,
    /// 其中走本地代理端口的条数。
    pub proxied: usize,
    /// 其中连本地/私网地址的条数。
    pub local: usize,
    /// 直连公网的记录（最多列 [`MAX_LISTED`] 条，总数见 `direct_total`）。
    pub direct: Vec<LeakConn>,
    pub direct_total: usize,
    pub note: String,
}

/// 列表最多展示的直连条数（计数仍是全量）。
pub const MAX_LISTED: usize = 8;

/// 是否 fake-IP 段（Clash/mihomo 默认用 198.18.0.0/15，也有用 198.19）。
fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

/// 是否本机/私网/链路本地。
pub fn is_local_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified()
}

/// 分类一条连接的对端。
pub fn classify(remote: Ipv4Addr, port: u16, proxy_port: u16) -> Remote {
    if remote.is_loopback() && port == proxy_port {
        Remote::Proxy
    } else if is_local_v4(remote) || is_fake_ip_v4(remote) {
        Remote::Local
    } else {
        Remote::Public
    }
}

/// 汇总一轮观察。
///
/// `mode` 为接入路径标签；只有 `system_proxy` 才具备判定条件——TUN 模式下应用的
/// 对端本来就是公网地址（流量被虚拟网卡接管），拿公网对端当泄露会全线误报。
/// `proxy_port` 是系统代理端口（0 表示未知，此时没有任何连接会被归为 `Proxy`）。
pub fn summarize(
    mode: &str,
    proxy_port: u16,
    conns: &[TcpConn],
    agents: &BTreeMap<u32, String>,
) -> LeakReport {
    let applicable = mode == "system_proxy";
    if !applicable {
        return LeakReport {
            applicable: false,
            mode: mode.to_string(),
            agent_conns: 0,
            proxied: 0,
            local: 0,
            direct: Vec::new(),
            direct_total: 0,
            note: match mode {
                "tun" => "TUN 模式下应用对端本来就是公网地址，不做直连判定".to_string(),
                "uncovered" => "未接入代理链路，直连不可避免，不做泄露判定".to_string(),
                _ => "接入路径无法确认，不做直连判定".to_string(),
            },
        };
    }

    let mut proxied = 0;
    let mut local = 0;
    let mut direct = Vec::new();
    let mut agent_conns = 0;
    for conn in conns {
        let Some(agent) = agents.get(&conn.pid) else {
            continue;
        };
        agent_conns += 1;
        match classify(conn.remote, conn.port, proxy_port) {
            Remote::Proxy => proxied += 1,
            Remote::Local => local += 1,
            Remote::Public => {
                if direct.len() < MAX_LISTED {
                    direct.push(LeakConn {
                        pid: conn.pid,
                        agent: agent.clone(),
                        remote: conn.remote.to_string(),
                        port: conn.port,
                    });
                }
            }
        }
    }
    let direct_total = conns
        .iter()
        .filter(|conn| {
            agents.contains_key(&conn.pid)
                && classify(conn.remote, conn.port, proxy_port) == Remote::Public
        })
        .count();
    LeakReport {
        applicable: true,
        mode: mode.to_string(),
        agent_conns,
        proxied,
        local,
        direct,
        direct_total,
        note: if direct_total == 0 {
            "被守护进程没有直连公网的连接".to_string()
        } else {
            format!("发现 {direct_total} 条绕过代理的直连")
        },
    }
}

/// 采集被守护进程的 ESTABLISHED 连接（IPv4 TCP）。
///
/// 采集失败返回空表：观察功能宁可少报，**不能**因此熔断。
pub fn collect_agent_conns() -> Vec<TcpConn> {
    collect_established_ipv4().unwrap_or_default()
}

/// 读全机 IPv4 TCP ESTABLISHED 连接（带 owning pid）。
#[cfg(windows)]
fn collect_established_ipv4() -> Option<Vec<TcpConn>> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    /// TCP 状态：ESTABLISHED。
    const ESTABLISHED: u32 = 5;

    let mut size: u32 = 0;
    // 第一次调用只为拿所需缓冲区大小。
    let first = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return None;
    }
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buffer = vec![0u8; size as usize];
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != NO_ERROR {
        return None;
    }
    // 表头：u32 条目数，随后是连续的 MIB_TCPROW_OWNER_PID。
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    let rows = unsafe {
        buffer
            .as_ptr()
            .add(std::mem::size_of::<u32>())
            .cast::<MIB_TCPROW_OWNER_PID>()
    };
    // 防御：条目数不能超过缓冲区实际能容纳的数量（表在两次调用之间可能变大）。
    let capacity =
        (buffer.len() - std::mem::size_of::<u32>()) / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let count = count.min(capacity);
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let row = unsafe { std::ptr::read_unaligned(rows.add(index)) };
        if row.dwState != ESTABLISHED {
            continue;
        }
        // dwRemoteAddr 是网络字节序（big-endian）的 IPv4。
        let octets = row.dwRemoteAddr.to_be_bytes();
        let port = u16::from_be(row.dwRemotePort as u16);
        out.push(TcpConn {
            pid: row.dwOwningPid,
            remote: Ipv4Addr::from(octets),
            port,
        });
    }
    Some(out)
}

#[cfg(not(windows))]
fn collect_established_ipv4() -> Option<Vec<TcpConn>> {
    None
}

/// 从系统代理设置里取端口（`ProxyServer` 的 `host:port` 或分号形式）。
pub fn proxy_port_from_evidence(evidence: &crate::egate_access::ProxyEvidence) -> u16 {
    use crate::egate_access::ProxyParse;
    match crate::egate_access::parse_proxy_server(evidence.server.as_deref()) {
        ProxyParse::Http(addr) => addr
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(pid: u32, remote: [u8; 4], port: u16) -> TcpConn {
        TcpConn {
            pid,
            remote: Ipv4Addr::from(remote),
            port,
        }
    }

    fn agents(pids: &[(u32, &str)]) -> BTreeMap<u32, String> {
        pids.iter()
            .map(|(pid, name)| (*pid, (*name).to_string()))
            .collect()
    }

    #[test]
    fn classify_proxy_local_and_public() {
        assert_eq!(classify(Ipv4Addr::LOCALHOST, 7890, 7890), Remote::Proxy);
        // 回环但不是代理端口：仍算本地（不是泄露）。
        assert_eq!(classify(Ipv4Addr::LOCALHOST, 1420, 7890), Remote::Local);
        assert_eq!(
            classify(Ipv4Addr::new(192, 168, 1, 5), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(10, 0, 0, 7), 443, 7890),
            Remote::Local
        );
        // fake-IP 段：Clash 的合成地址，不是真实公网。
        assert_eq!(
            classify(Ipv4Addr::new(198, 18, 0, 3), 443, 7890),
            Remote::Local
        );
        // 真实公网：泄露证据。
        assert_eq!(
            classify(Ipv4Addr::new(1, 1, 1, 1), 443, 7890),
            Remote::Public
        );
    }

    #[test]
    fn tun_mode_is_not_applicable_to_avoid_false_alarms() {
        let report = summarize(
            "tun",
            7890,
            &[conn(10, [1, 1, 1, 1], 443)],
            &agents(&[(10, "claude")]),
        );
        assert!(!report.applicable);
        assert_eq!(report.direct_total, 0, "TUN 下不能把公网对端当泄露");
        assert!(report.note.contains("TUN"));
    }

    #[test]
    fn uncovered_mode_is_not_applicable() {
        let report = summarize("uncovered", 7890, &[], &agents(&[]));
        assert!(!report.applicable);
        assert!(report.note.contains("未接入"));
    }

    #[test]
    fn only_guarded_pids_are_counted() {
        let conns = vec![
            conn(10, [1, 1, 1, 1], 443), // 被守护进程
            conn(99, [8, 8, 8, 8], 443), // 无关进程（浏览器等）
        ];
        let report = summarize("system_proxy", 7890, &conns, &agents(&[(10, "claude")]));
        assert_eq!(report.agent_conns, 1, "无关进程不能算进被守护连接");
        assert_eq!(report.direct_total, 1);
        assert_eq!(report.direct[0].agent, "claude");
    }

    #[test]
    fn direct_listing_is_capped_but_count_is_full() {
        let conns: Vec<TcpConn> = (0..12).map(|i| conn(10, [8, 8, 8, i as u8], 443)).collect();
        let report = summarize("system_proxy", 7890, &conns, &agents(&[(10, "claude")]));
        assert_eq!(report.direct.len(), MAX_LISTED, "列表最多 8 条");
        assert_eq!(report.direct_total, 12, "计数必须是全量");
    }

    #[test]
    fn proxied_and_local_are_counted_separately() {
        let conns = vec![
            conn(10, [127, 0, 0, 1], 7890),  // 走代理
            conn(10, [192, 168, 1, 2], 443), // 本地
            conn(10, [1, 1, 1, 1], 443),     // 直连
        ];
        let report = summarize("system_proxy", 7890, &conns, &agents(&[(10, "claude")]));
        assert_eq!(
            (report.proxied, report.local, report.direct_total),
            (1, 1, 1)
        );
    }

    #[test]
    fn unknown_proxy_port_never_classifies_as_proxy() {
        // 端口未知（0）：回环连接也只能算本地，不能误判成「走代理」。
        let report = summarize(
            "system_proxy",
            0,
            &[conn(10, [127, 0, 0, 1], 7890)],
            &agents(&[(10, "claude")]),
        );
        assert_eq!(report.proxied, 0);
        assert_eq!(report.local, 1);
    }

    #[test]
    fn clean_report_says_no_direct_connections() {
        let report = summarize(
            "system_proxy",
            7890,
            &[conn(10, [127, 0, 0, 1], 7890)],
            &agents(&[(10, "claude")]),
        );
        assert_eq!(report.direct_total, 0);
        assert!(report.note.contains("没有直连"));
    }

    #[test]
    fn proxy_port_is_parsed_from_evidence_forms() {
        use crate::egate_access::ProxyEvidence;
        let one = ProxyEvidence {
            enable: true,
            server: Some("127.0.0.1:7890".to_string()),
            autoconfig: None,
            overrides: None,
            complete: true,
            error: None,
        };
        assert_eq!(proxy_port_from_evidence(&one), 7890);
        let pair = ProxyEvidence {
            enable: true,
            server: Some("http=127.0.0.1:7891;https=127.0.0.1:7892".to_string()),
            autoconfig: None,
            overrides: None,
            complete: true,
            error: None,
        };
        assert_eq!(proxy_port_from_evidence(&pair), 7892, "https 段优先");
        let none = ProxyEvidence::default();
        assert_eq!(proxy_port_from_evidence(&none), 0);
    }
}
