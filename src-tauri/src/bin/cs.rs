//! `cs.exe` —— 控制台子系统命令行小程序（J-1）。
//!
//! 与 GUI 主程序（`windows_subsystem = "windows"`，默认无控制台）不同：本目标
//! **不设置** `windows_subsystem`，使用默认控制台，启动即自带控制台与有效标准句柄。
//! 与主程序共用同一个库（`claude_switcher_lib`），同步执行 CLI 子命令，并用
//! `std::process::exit` 透传真实退出码，便于在脚本 / CI 中判断成败。
//!
//! 支持：`--list` / `--status` / `--switch <名称>`（`run` 子命令在 F-1 加入）。

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = claude_switcher_lib::cli_console(&args);
    std::process::exit(code);
}
