fn main() {
    // C-6：挂自定义清单（asInvoker / supportedOS / longPathAware），
    // 保留 Common-Controls 6.0 依赖（Tauri 对话框 API 需要）。
    //
    // assemblyIdentity 的 version 由 CARGO_PKG_VERSION 生成，不写死在 manifest 里：
    // 手改版本号每次发版都要惦记一遍，漏改会让安装包里的清单版本与真实版本不一致
    // （排障时看到的是错版本号）。四段式 version 要求 a.b.c.d，补第四个 0。
    let manifest = include_str!("windows-app.manifest")
        .replace("0.2.0.0", &format!("{}.0", env!("CARGO_PKG_VERSION")));
    let attrs = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(&manifest));
    tauri_build::try_build(attrs).expect("tauri build failed");
}
