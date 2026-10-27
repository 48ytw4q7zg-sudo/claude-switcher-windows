fn main() {
    // C-6：挂自定义清单（asInvoker / supportedOS / longPathAware），
    // 保留 Common-Controls 6.0 依赖（Tauri 对话框 API 需要）。
    let attrs = tauri_build::Attributes::new().windows_attributes(
        tauri_build::WindowsAttributes::new().app_manifest(include_str!("windows-app.manifest")),
    );
    tauri_build::try_build(attrs).expect("tauri build failed");
}
