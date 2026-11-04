//! 命令行入口：`--list` / `--status` / `--switch <名称>`。
//!
//! 发布版是 GUI 子系统（`windows_subsystem = "windows"`），默认没有控制台。
//! 命中 CLI 子命令时先 `AttachConsole(ATTACH_PARENT_PROCESS)` 再 `println!`，
//! 最后以退出码 `std::process::exit`。控制台附加/输出的真实行为需实机验证。

use std::io::Write;

use crate::platform::imp;
use crate::store;

/// 解析出的 CLI 子命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    List,
    Status,
    /// 后接账号名称（精确匹配）。
    Switch(String),
    /// K-5：后接账号 id（UUID），改名/引号不影响，开始菜单快捷方式专用。
    SwitchId(String),
    /// 出口门禁：单次检查，JSON 输出；退出码 0 通过 / 2 未通过。
    EgateCheck,
    /// 出口门禁：急救——恢复网络并解除全部隔离。
    EgateRestore,
    /// 出口门禁：发送一条测试通知，后接类别。
    EgateNotifyTest(String),
}

/// 从 argv 解析子命令（不假设 argv[0] 之外的位置）。无匹配返回 None。
pub fn parse(args: &[String]) -> Option<CliCommand> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--list" => return Some(CliCommand::List),
            "--status" => return Some(CliCommand::Status),
            "--switch" => {
                // 名称缺省为空串，resolve 时会给出明确错误。
                let name = iter.next().cloned().unwrap_or_default();
                return Some(CliCommand::Switch(name));
            }
            "--switch-id" => {
                // K-5：id 缺省为空串，resolve 时给出明确错误。
                let id = iter.next().cloned().unwrap_or_default();
                return Some(CliCommand::SwitchId(id));
            }
            // 出口门禁：脚本化入口（批处理 / 前置流水线）。
            "--egate-check" => return Some(CliCommand::EgateCheck),
            "--egate-restore" => return Some(CliCommand::EgateRestore),
            "--egate-notify-test" => {
                let kind = iter.next().cloned().unwrap_or_default();
                return Some(CliCommand::EgateNotifyTest(kind));
            }
            _ => {}
        }
    }
    None
}

/// 执行只读子命令（list / status），返回进程退出码。
pub fn run_readonly(cmd: &CliCommand) -> i32 {
    let attached = imp::attach_parent_console();
    let code = match cmd {
        CliCommand::List => print_list(),
        CliCommand::Status => print_status(),
        CliCommand::EgateCheck => run_egate_check(),
        CliCommand::EgateRestore => run_egate_restore(),
        // 写路径/需要 GUI 上下文的命令不应走这里；保守返回参数错误码。
        CliCommand::Switch(_) | CliCommand::SwitchId(_) | CliCommand::EgateNotifyTest(_) => 2,
    };
    let _ = std::io::stdout().flush();
    if !attached {
        // 没有可附加的父控制台（如从运行框直接启动），无法输出；
        // 不视为致命，仍返回计算出的退出码。
    }
    code
}

/// 出口门禁单次检查：JSON 输出，退出码 0 通过 / 2 未通过。
///
/// 与上游 `--check` 对齐：调用方只看退出码就能做前置判断（例如「出口不对就
/// 不启动应用」），不需要解析 JSON。
fn run_egate_check() -> i32 {
    let config = crate::appconfig::load();
    let targets = if config.egate_targets.is_empty() {
        crate::egate_defaults::builtin_targets()
    } else {
        config.egate_targets
    };
    let mut streaks = crate::egate_streaks()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let report = crate::egate_check::run_round(
        &targets,
        &mut streaks,
        config.egate_enforce_access,
        config.egate_trip_threshold,
    );
    drop(streaks);
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            match report.overall.verdict {
                crate::egate::Verdict::Pass => 0,
                _ => 2,
            }
        }
        Err(error) => {
            eprintln!("序列化检查结果失败: {error}");
            1
        }
    }
}

/// 出口门禁急救：恢复网络 + 解除全部隔离（`--restore` 的等价入口）。
///
/// 与上游一致：**先恢复网络**（断网状态下没人能来点界面），再解隔离。
fn run_egate_restore() -> i32 {
    let mut code = 0;
    let (network_ok, network_note) = crate::egate_netcut::restore();
    if !network_ok {
        eprintln!("恢复网络失败: {network_note}");
        code = 1;
    }
    match crate::egate_trip::release_all() {
        Ok(removed) => {
            crate::egate_monitor::clear_tripped();
            println!("已恢复网络并解除隔离（清理 {removed} 条规则）");
        }
        Err(error) => {
            eprintln!("解除隔离失败: {error}");
            code = 1;
        }
    }
    code
}

fn print_list() -> i32 {
    let (profiles, current) = match store::read_lightweight() {
        Ok(value) => value,
        Err(e) => {
            println!("读取账号列表失败: {e}");
            return 1;
        }
    };
    if profiles.is_empty() {
        println!("（暂无已保存账号）");
        return 0;
    }
    for profile in profiles {
        let mark = if current.as_deref() == Some(profile.id.as_str()) {
            "[*]"
        } else {
            "[ ]"
        };
        let email = profile.email.as_deref().unwrap_or("-");
        println!("{mark} {} <{email}> id={}", profile.name, profile.id);
    }
    0
}

fn print_status() -> i32 {
    let (profiles, current) = match store::read_lightweight() {
        Ok(value) => value,
        Err(e) => {
            println!("读取状态失败: {e}");
            return 1;
        }
    };
    match current {
        Some(id) => match profiles.iter().find(|p| p.id == id) {
            Some(profile) => {
                println!("当前账号: {} (id={})", profile.name, profile.id);
                if let Some(email) = profile.email.as_deref() {
                    println!("邮箱: {email}");
                }
            }
            None => println!("当前账号 id={id}（列表中缺失，数据可能不一致）"),
        },
        None => println!("当前没有全局账号（尚未切换）"),
    }
    0
}

/// 按名称精确匹配（trim 后比较），返回 profile id。
pub fn resolve_profile_id(name: &str) -> Result<String, String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("--switch 缺少账号名称".to_string());
    }
    let (profiles, _) = store::read_lightweight()?;
    profiles
        .iter()
        .find(|p| p.name == clean)
        .map(|p| p.id.clone())
        .ok_or_else(|| format!("找不到名为「{clean}」的账号，可用 --list 查看已保存账号"))
}

/// 唯一实例路径：执行切换并打印结果，返回进程退出码。
pub fn run_switch_first_instance(name: &str) -> i32 {
    let _attached = imp::attach_parent_console();
    let id = match resolve_profile_id(name) {
        Ok(id) => id,
        Err(e) => {
            println!("{e}");
            let _ = std::io::stdout().flush();
            return 1;
        }
    };
    match crate::switch_profile_blocking(id) {
        Ok(result) => {
            println!(
                "已切换到「{}」。{}",
                result.switched_to, result.restart_hint
            );
            let _ = std::io::stdout().flush();
            0
        }
        Err(e) => {
            println!("切换失败: {e}");
            let _ = std::io::stdout().flush();
            1
        }
    }
}

/// 已有实例运行时：把切换请求转交给运行实例（后台线程执行 + 通知 + 重建菜单），
/// 避免两个进程同时改账号库。
pub fn forward_switch(app: &tauri::AppHandle, name: &str) {
    match resolve_profile_id(name) {
        Ok(id) => crate::tray::handle_tray_switch(app, &id),
        Err(e) => crate::log_error(&format!("CLI 转交切换失败: {e}")),
    }
}

/// K-5：校验账号 id 确实存在（trim 后比较），返回该 id。
pub fn resolve_profile_id_by_id(raw_id: &str) -> Result<String, String> {
    let clean = raw_id.trim();
    if clean.is_empty() {
        return Err("--switch-id 缺少账号 id".to_string());
    }
    let (profiles, _) = store::read_lightweight()?;
    if profiles.iter().any(|p| p.id == clean) {
        Ok(clean.to_string())
    } else {
        Err(format!(
            "找不到 id 为「{clean}」的账号，可用 --list 查看已保存账号"
        ))
    }
}

/// K-5：唯一实例下按 id 执行切换并打印结果，返回退出码。
pub fn run_switch_id_first_instance(raw_id: &str) -> i32 {
    let _attached = imp::attach_parent_console();
    let id = match resolve_profile_id_by_id(raw_id) {
        Ok(id) => id,
        Err(e) => {
            println!("{e}");
            let _ = std::io::stdout().flush();
            return 1;
        }
    };
    match crate::switch_profile_blocking(id.clone()) {
        Ok(result) => {
            println!(
                "已切换到「{}」。{}",
                result.switched_to, result.restart_hint
            );
            let _ = std::io::stdout().flush();
            0
        }
        Err(e) => {
            println!("切换失败: {e}");
            let _ = std::io::stdout().flush();
            1
        }
    }
}

/// K-5：已有实例运行时，按 id 把切换请求转交给运行实例。
pub fn forward_switch_id(app: &tauri::AppHandle, raw_id: &str) {
    match resolve_profile_id_by_id(raw_id) {
        Ok(id) => crate::tray::handle_tray_switch(app, &id),
        Err(e) => crate::log_error(&format!("CLI 转交切换失败: {e}")),
    }
}

/// 控制台子系统入口（cs.exe，J-1）。
///
/// cs 是默认控制台程序，启动时已自带控制台、标准句柄有效，因此这里直接解析
/// 子命令并执行；`run_readonly` / `run_switch_first_instance` 内部的
/// `AttachConsole` 会因已有控制台而失败，但不影响输出（句柄本就有效）。
/// 返回真实进程退出码，由 bin 用 `std::process::exit` 透传。
pub fn run_console(args: &[String]) -> i32 {
    // cs run [透传参数...]：在当前目录绑定的账号下启动 claude（F-1）。
    // K-2：只把第一个参数（argv[1]）当子命令，避免账号名恰好叫 run 时误判。
    if args.get(1).map(String::as_str) == Some("run") {
        let extra: Vec<String> = args[2..].to_vec();
        let start = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        return match crate::dirbinding::run_bound_account(&start, &extra) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{e}");
                let _ = std::io::stderr().flush();
                1
            }
        };
    }
    match parse(args) {
        Some(CliCommand::List) => run_readonly(&CliCommand::List),
        Some(CliCommand::Status) => run_readonly(&CliCommand::Status),
        Some(CliCommand::Switch(name)) => run_switch_first_instance(&name),
        Some(CliCommand::SwitchId(id)) => run_switch_id_first_instance(&id),
        Some(CliCommand::EgateCheck) => run_readonly(&CliCommand::EgateCheck),
        Some(CliCommand::EgateRestore) => run_readonly(&CliCommand::EgateRestore),
        // 通知测试需要 GUI 的 AppHandle，走主程序而非 CLI 进程。
        Some(CliCommand::EgateNotifyTest(_)) => {
            print_usage();
            2
        }
        None => {
            print_usage();
            2
        }
    }
}

/// 打印用法（无子命令时）。
fn print_usage() {
    println!(
        "Claude Switcher (cs)\n\
         用法:\n\
         \x20 cs --list              列出已保存账号\n\
         \x20 cs --status            显示当前全局账号\n\
         \x20 cs --switch <名称>     切换到指定账号\n\
         \x20 cs --switch-id <id>    按账号 id 切换（开始菜单快捷方式用）\n\
         \x20 cs run                 在当前目录绑定账号下启动 claude"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_detects_each_subcommand() {
        assert_eq!(parse(&argv(&["exe", "--list"])), Some(CliCommand::List));
        assert_eq!(parse(&argv(&["exe", "--status"])), Some(CliCommand::Status));
        assert_eq!(
            parse(&argv(&["exe", "--switch", "work"])),
            Some(CliCommand::Switch("work".to_string()))
        );
    }

    #[test]
    fn parse_detects_egate_subcommands() {
        assert_eq!(
            parse(&argv(&["exe", "--egate-check"])),
            Some(CliCommand::EgateCheck)
        );
        assert_eq!(
            parse(&argv(&["exe", "--egate-restore"])),
            Some(CliCommand::EgateRestore)
        );
        assert_eq!(
            parse(&argv(&["exe", "--egate-notify-test", "trip"])),
            Some(CliCommand::EgateNotifyTest("trip".to_string()))
        );
        // 缺类别时给空串，由调用方报参数错误，不静默当成默认类别。
        assert_eq!(
            parse(&argv(&["exe", "--egate-notify-test"])),
            Some(CliCommand::EgateNotifyTest(String::new()))
        );
    }

    #[test]
    fn parse_switch_consumes_only_next_token() {
        let args = argv(&["exe", "--switch", "acct", "--list"]);
        assert_eq!(parse(&args), Some(CliCommand::Switch("acct".to_string())));
    }

    #[test]
    fn parse_switch_without_name_is_blank_switch() {
        assert_eq!(
            parse(&argv(&["exe", "--switch"])),
            Some(CliCommand::Switch(String::new()))
        );
    }

    #[test]
    fn parse_switch_id_consumes_only_next_token() {
        assert_eq!(
            parse(&argv(&["exe", "--switch-id", "uuid-123", "--list"])),
            Some(CliCommand::SwitchId("uuid-123".to_string()))
        );
        assert_eq!(
            parse(&argv(&["exe", "--switch-id"])),
            Some(CliCommand::SwitchId(String::new()))
        );
    }

    #[test]
    fn resolve_switch_id_rejects_blank_before_touching_store() {
        assert!(resolve_profile_id_by_id("   ").is_err());
        assert!(resolve_profile_id_by_id("").is_err());
    }

    #[test]
    fn parse_returns_none_without_subcommand() {
        assert_eq!(parse(&argv(&["exe", "--guard", "--autostart"])), None);
    }

    #[test]
    fn resolve_rejects_blank_name_before_touching_store() {
        assert!(resolve_profile_id("   ").is_err());
        assert!(resolve_profile_id("").is_err());
    }
}
