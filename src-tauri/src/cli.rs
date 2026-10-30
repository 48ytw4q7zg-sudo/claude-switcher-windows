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
        // 写路径不应走这里；保守返回参数错误码。
        CliCommand::Switch(_) => 2,
    };
    let _ = std::io::stdout().flush();
    if !attached {
        // 没有可附加的父控制台（如从运行框直接启动），无法输出；
        // 不视为致命，仍返回计算出的退出码。
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
    fn parse_returns_none_without_subcommand() {
        assert_eq!(parse(&argv(&["exe", "--guard", "--autostart"])), None);
    }

    #[test]
    fn resolve_rejects_blank_name_before_touching_store() {
        assert!(resolve_profile_id("   ").is_err());
        assert!(resolve_profile_id("").is_err());
    }
}
