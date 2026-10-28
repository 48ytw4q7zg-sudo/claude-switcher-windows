fn main() {
    // C-6：挂自定义清单（asInvoker / supportedOS / longPathAware），
    // 保留 Common-Controls 6.0 依赖（Tauri 对话框 API 需要）。
    //
    // 版本号由 CARGO_PKG_VERSION 生成并替换 manifest 里的 {{VERSION}} 占位符：
    // 手改版本号每次发版都要惦记一遍，漏改会让安装包里的清单版本与真实版本不一致
    // （排障时看到的是错版本号）。
    //
    // 程序集版本必须是「四段纯数字」（a.b.c.d）。预发布后缀（0.3.0-beta.1）不是
    // 合法程序集版本，直接拼上去会让整份清单失效——因此只取 '-' / '+' 之前的数字
    // 部分，不足四段补 0。
    let numeric = env!("CARGO_PKG_VERSION")
        .split(['-', '+'])
        .next()
        .unwrap_or("0.0.0");
    let mut parts: Vec<&str> = numeric.split('.').collect();
    while parts.len() < 4 {
        parts.push("0");
    }
    let assembly_version = parts[..4].join(".");

    let manifest = include_str!("windows-app.manifest").replace("{{VERSION}}", &assembly_version);
    assert!(
        !manifest.contains("{{VERSION}}"),
        "windows-app.manifest 里的 {{{{VERSION}}}} 占位符必须被替换"
    );

    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(&manifest));
    tauri_build::try_build(attrs).expect("tauri build failed");
}
