//! 托盘图标、弹窗定位、刷新线程。

use std::sync::Mutex;
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::webview::PageLoadEvent;
use tauri::{
    AppHandle, Manager, PhysicalPosition, Position, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};

use crate::store;
use crate::usage;

/// 弹窗逻辑尺寸（logical px），创建窗口与定位共用，不再两处硬编码。
const POPUP_WIDTH: f64 = 360.0;
const POPUP_HEIGHT: f64 = 410.0;

/// 弹窗因失焦隐藏后的防抖窗口：Windows 上点托盘图标会先让弹窗失焦隐藏，
/// 随后 Click 事件到达——没有防抖时 toggle 会把刚隐藏的弹窗又打开，
/// 表现为「点图标想关却关不掉」。
const POPUP_REOPEN_DEBOUNCE: StdDuration = StdDuration::from_millis(500);

static POPUP_HIDDEN_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// tooltip 预算：Windows 托盘约 127 字符；优先保留 5 小时与 7 天用量。
const TOOLTIP_MAX_CHARS: usize = 120;

pub fn refresh_tray_status(app: &tauri::AppHandle) -> Result<(), String> {
    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };
    let tray_usage = usage::claude_usage_snapshot()?;
    // H-2：把当前账号用量落进独立 usage-cache.json（best-effort，不碰账号库）。
    if let Err(e) = usage::record_usage_from_snapshot(&tray_usage) {
        crate::log_error(&format!("记录用量缓存失败: {e}"));
    }
    let session = usage::compact_token_count(tray_usage.session.totals.total_tokens);
    let weekly = usage::compact_token_count(tray_usage.weekly.totals.total_tokens);
    let mut tooltip = format!("Claude Switcher\n近 5 小时: {session}\n近 7 天: {weekly}");
    if let Some(model) = tray_usage.top_model.as_deref() {
        let model = if model.chars().count() > 40 {
            format!("{}…", model.chars().take(40).collect::<String>())
        } else {
            model.to_string()
        };
        let candidate = format!("\n常用模型: {model}");
        if tooltip.chars().count() + candidate.chars().count() <= TOOLTIP_MAX_CHARS {
            tooltip.push_str(&candidate);
        }
    }
    tray.set_tooltip(Some(tooltip))
        .map_err(|e| format!("更新托盘提示失败: {e}"))?;
    Ok(())
}

/// 托盘弹窗定位：以点击坐标所在显示器为准（不回退主屏），
/// 使用工作区（排除任务栏）夹紧；任务栏在侧/顶部时也能正确弹出。
fn position_tray_popup(
    window: &WebviewWindow,
    tray_position: PhysicalPosition<f64>,
) -> Result<(), String> {
    let scale = window.scale_factor().unwrap_or(1.0);
    let popup_w = POPUP_WIDTH * scale;
    let popup_h = POPUP_HEIGHT * scale;

    let mut x = tray_position.x - popup_w / 2.0;
    // Windows：弹窗向上展开到托盘图标上方。
    let mut y = tray_position.y - popup_h - 4.0 * scale;

    // 点击坐标所在显示器（多显示器时弹窗跟着图标走）。
    let monitor = window
        .monitor_from_point(tray_position.x, tray_position.y)
        .or_else(|_| window.primary_monitor())
        .ok()
        .flatten();
    if let Some(monitor) = monitor {
        // Tauri 2 的 Monitor::work_area() 即物理像素工作区（排除任务栏），
        // 比 SPI_GETWORKAREA 更准（多屏/多 DPI 都正确）。
        let work = monitor.work_area();
        let min_x = work.position.x as f64;
        let max_x = work.position.x as f64 + work.size.width as f64 - popup_w;
        x = x.clamp(min_x, max_x.max(min_x));
        let min_y = work.position.y as f64;
        let max_y = work.position.y as f64 + work.size.height as f64 - popup_h;
        y = y.clamp(min_y, max_y.max(min_y));
    }

    window
        .set_position(Position::Physical(PhysicalPosition::new(
            x as i32, y as i32,
        )))
        .map_err(|e| format!("定位托盘弹窗失败: {e}"))
}

pub fn toggle_tray_popup(app: &AppHandle, tray_position: PhysicalPosition<f64>) {
    // 防抖：弹窗刚因点击托盘失焦而隐藏时，这次的 Click 意图是「保持关闭」。
    if let Ok(hidden_at) = POPUP_HIDDEN_AT.lock() {
        if hidden_at.is_some_and(|at| at.elapsed() < POPUP_REOPEN_DEBOUNCE) {
            return;
        }
    }

    let label = "tray-popup";
    if let Some(window) = app.get_webview_window(label) {
        let is_tray_popup = window
            .url()
            .map(|url| url.as_str().contains("window=tray-popup"))
            .unwrap_or(false);
        if !is_tray_popup {
            let _ = window.close();
        } else {
            if window.is_visible().unwrap_or(false) {
                let _ = window.hide();
                return;
            }
            let _ = position_tray_popup(&window, tray_position);
            let _ = window.show();
            let _ = window.set_focus();
            return;
        }
    }

    match WebviewWindowBuilder::new(
        app,
        label,
        WebviewUrl::App("index.html?window=tray-popup".into()),
    )
    .title("Claude Switcher Status")
    .inner_size(POPUP_WIDTH, POPUP_HEIGHT)
    .resizable(false)
    .decorations(false)
    .transparent(true)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .visible(false)
    .on_page_load(|window, payload| {
        if matches!(payload.event(), PageLoadEvent::Finished) {
            let _ = window.show();
            let _ = window.set_focus();
        }
    })
    .build()
    {
        Ok(window) => {
            let window_clone = window.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::Focused(false) = event {
                    let _ = window_clone.hide();
                    if let Ok(mut hidden_at) = POPUP_HIDDEN_AT.lock() {
                        *hidden_at = Some(Instant::now());
                    }
                }
            });
            let _ = position_tray_popup(&window, tray_position);
        }
        Err(error) => crate::log_error(&format!("创建托盘弹窗失败: {error}")),
    }
}

pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    if let Some(popup) = app.get_webview_window("tray-popup") {
        let _ = popup.hide();
    }
}

pub fn quit_app(app: &AppHandle) {
    app.exit(0);
}

/// 托盘菜单账号项 id 前缀，后接 profile id；点击即一键切换到该账号。
pub const SWITCH_MENU_ID_PREFIX: &str = "tray-switch-";
/// 托盘菜单里账号名的最大字符数（超长截断，避免菜单过宽）。
const MENU_LABEL_MAX_CHARS: usize = 24;
/// 账号数超过这个值时，账号列表收进「切换账号」子菜单。
const MENU_FLAT_MAX_PROFILES: usize = 10;

/// 截断超长账号名（按字符而非字节，含中文不 panic）。
fn truncate_menu_label(label: &str) -> String {
    if label.chars().count() <= MENU_LABEL_MAX_CHARS {
        return label.to_string();
    }
    let head: String = label.chars().take(MENU_LABEL_MAX_CHARS).collect();
    format!("{head}…")
}

/// 账号菜单项的显示文本：当前账号前缀「●」，名称超长截断。
fn account_menu_label(name: &str, is_current: bool) -> String {
    let marker = if is_current { "● " } else { "" };
    format!("{marker}{}", truncate_menu_label(name))
}

/// 账号数是否需要收进子菜单（> MENU_FLAT_MAX_PROFILES）。
fn account_list_needs_submenu(profile_count: usize) -> bool {
    profile_count > MENU_FLAT_MAX_PROFILES
}

/// 纯函数：由轻量账号列表生成 (menu_id, label) 行；当前账号打 ●。
fn account_menu_rows(
    profiles: &[store::LightProfile],
    current_id: Option<&str>,
) -> Vec<(String, String)> {
    profiles
        .iter()
        .map(|profile| {
            let is_current = current_id == Some(profile.id.as_str());
            (
                format!("{SWITCH_MENU_ID_PREFIX}{}", profile.id),
                account_menu_label(&profile.name, is_current),
            )
        })
        .collect()
}

/// 构建托盘右键菜单：账号列表（当前账号 ● 标记，点击一键切换）+ 打开/刷新/退出。
/// best-effort：轻量读取失败时只记日志并返回不含账号项的菜单，不解密账号库、不 panic。
fn build_tray_menu<R: tauri::Runtime>(
    app: &AppHandle<R>,
    tray: &tauri::tray::TrayIcon<R>,
) -> Result<(), String> {
    let (profiles, current_id) = match store::read_lightweight() {
        Ok(value) => value,
        Err(e) => {
            crate::log_error(&format!(
                "读取账号轻量元数据失败，托盘菜单不含账号列表: {e}"
            ));
            (Vec::new(), None)
        }
    };
    let current_id = current_id.as_deref();

    // 账号菜单项（按轻量元数据动态生成；不解密 keychain）。
    let account_items: Vec<tauri::menu::MenuItem<R>> = account_menu_rows(&profiles, current_id)
        .into_iter()
        .map(|(id, label)| {
            tauri::menu::MenuItem::with_id(app, id, label, true, None::<&str>)
                .map_err(|e| format!("创建账号菜单项失败: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 组装菜单引用（所有 owned 项在本函数内保持存活）。
    let mut menu_refs: Vec<&dyn tauri::menu::IsMenuItem<R>> = Vec::new();
    // 提升到函数作用域：子菜单与分隔符在下方 if 块内创建，
    // 但引用要一直活到 Menu::with_items。
    let submenu;
    let sep;

    if !account_items.is_empty() {
        if account_list_needs_submenu(account_items.len()) {
            let inner: Vec<&dyn tauri::menu::IsMenuItem<R>> =
                account_items.iter().map(|i| i as &_).collect();
            submenu = tauri::menu::Submenu::with_items(app, "切换账号", true, &inner)
                .map_err(|e| format!("创建账号子菜单失败: {e}"))?;
            menu_refs.push(&submenu);
        } else {
            for item in &account_items {
                menu_refs.push(item);
            }
        }
        sep = tauri::menu::PredefinedMenuItem::separator(app)
            .map_err(|e| format!("创建分隔符失败: {e}"))?;
        menu_refs.push(&sep);
    }

    let open_item =
        tauri::menu::MenuItem::with_id(app, "tray-open", "打开主窗口", true, None::<&str>)
            .map_err(|e| format!("创建菜单项失败: {e}"))?;
    let refresh_item =
        tauri::menu::MenuItem::with_id(app, "tray-refresh", "刷新用量", true, None::<&str>)
            .map_err(|e| format!("创建菜单项失败: {e}"))?;
    let quit_item = tauri::menu::MenuItem::with_id(
        app,
        "tray-quit",
        "退出 Claude Switcher",
        true,
        None::<&str>,
    )
    .map_err(|e| format!("创建菜单项失败: {e}"))?;
    menu_refs.push(&open_item);
    menu_refs.push(&refresh_item);
    menu_refs.push(&quit_item);

    let menu =
        tauri::menu::Menu::with_items(app, &menu_refs).map_err(|e| format!("组装菜单失败: {e}"))?;
    tray.set_menu(Some(menu))
        .map_err(|e| format!("挂载菜单失败: {e}"))
}

/// 一键切换后由外部调用：重建托盘菜单（刷新当前账号 ● 标记）。
pub fn rebuild_tray_menu(app: &tauri::AppHandle) -> Result<(), String> {
    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };
    build_tray_menu(app, &tray)
}

/// 托盘一键切换：在后台线程执行切换，随后重建菜单并弹系统通知。
pub fn handle_tray_switch(app: &tauri::AppHandle, profile_id: &str) {
    let handle = app.clone();
    let profile_id = profile_id.to_string();
    thread::spawn(move || {
        let result = crate::switch_profile_blocking(profile_id);
        // 无论成功失败都重建菜单（成功时刷新 ● 标记）。
        if let Err(e) = rebuild_tray_menu(&handle) {
            crate::log_error(&format!("重建托盘菜单失败: {e}"));
        }
        notify_switch_result(&handle, &result);
    });
}

/// 用系统通知展示一键切换结果。
fn notify_switch_result(app: &tauri::AppHandle, result: &Result<crate::SwitchResult, String>) {
    use tauri_plugin_notification::NotificationExt;
    let (title, body) = match result {
        Ok(switch) => (
            "账号切换成功",
            format!(
                "已切换到「{}」，请重启 Claude Code 会话",
                switch.switched_to
            ),
        ),
        Err(e) => ("账号切换失败", e.clone()),
    };
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        crate::log_error(&format!("发送切换通知失败: {e}"));
    }
}

pub fn install_tray_handlers(app: &mut tauri::App) -> Result<(), String> {
    let app_handle = app.handle().clone();
    if let Some(tray) = app_handle.tray_by_id("main") {
        let _ = tray.set_tooltip(Some("Claude Switcher".to_string()));
        // tauri.conf.json 里的 tray.png 是单色模板图标，在深色任务栏上看不清。
        // 改用多尺寸彩色 ICO（16/24/32/48/64/256），高 DPI 与不同任务栏尺寸下都清晰。
        if let Ok(icon) = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.ico")) {
            let _ = tray.set_icon(Some(icon));
        }

        // Windows 习惯：右键托盘出菜单（账号列表 + 打开主窗 / 刷新 / 退出）。
        // 菜单构建失败不阻断托盘初始化（托盘本体已经可用），只打日志。
        if let Err(error) = build_tray_menu(&app_handle, &tray) {
            crate::log_error(&format!("构建托盘菜单失败: {error}"));
        }
    }

    let refresh_handle = app_handle.clone();
    thread::spawn(move || {
        let _ = refresh_tray_status(&refresh_handle);
        // 额度阈值通知（P1-4）：随 60s 刷新一起评估，内部按周期去重。
        let _ = crate::notify_state::evaluate_quota_notification(&refresh_handle);
        loop {
            thread::sleep(StdDuration::from_secs(60));
            let _ = refresh_tray_status(&refresh_handle);
            let _ = crate::notify_state::evaluate_quota_notification(&refresh_handle);
        }
    });

    app.on_tray_icon_event(|app, event| {
        match event {
            // 左键单击：切换用量弹窗。
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                position,
                ..
            } => toggle_tray_popup(app, position),
            // 左键双击：直接打开主窗口（Windows 用户对托盘图标的习惯操作）。
            // 先把用量弹窗关掉：双击的前两次 Click 已经把它打开又关上，
            // 不显式隐藏的话主窗口与弹窗会同时可见。
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => {
                if let Some(popup) = app.get_webview_window("tray-popup") {
                    let _ = popup.hide();
                }
                show_main_window(app);
            }
            _ => {}
        }
    });

    app.on_menu_event(|app, event| {
        let id = event.id().as_ref();
        // 账号菜单项：一键切换（后台线程执行 + 重建菜单 + 通知）。
        if let Some(profile_id) = id.strip_prefix(SWITCH_MENU_ID_PREFIX) {
            handle_tray_switch(app, profile_id);
            return;
        }
        match id {
            "tray-open" => show_main_window(app),
            "tray-refresh" => {
                let handle = app.clone();
                thread::spawn(move || {
                    let _ = refresh_tray_status(&handle);
                });
            }
            "tray-quit" => quit_app(app),
            _ => {}
        }
    });

    Ok(())
}

#[cfg(test)]
mod menu_tests {
    use super::*;

    #[test]
    fn current_account_marked_with_dot() {
        assert_eq!(account_menu_label("美国号", true), "● 美国号");
        assert_eq!(account_menu_label("美国号", false), "美国号");
    }

    #[test]
    fn long_name_truncated_by_chars() {
        let long = "a".repeat(30);
        let out = account_menu_label(&long, false);
        assert_eq!(out.chars().count(), MENU_LABEL_MAX_CHARS + 1); // 24 + …
        assert!(out.ends_with('…'));
        // 当前标记 + 截断仍正常。
        let out = account_menu_label(&long, true);
        assert!(out.starts_with("● "));
    }

    #[test]
    fn submenu_used_only_above_threshold() {
        assert!(!account_list_needs_submenu(0));
        assert!(!account_list_needs_submenu(10));
        assert!(account_list_needs_submenu(11));
    }

    #[test]
    fn switch_id_prefix_stable() {
        assert_eq!(SWITCH_MENU_ID_PREFIX, "tray-switch-");
    }

    #[test]
    fn account_rows_prefix_ids_and_mark_current() {
        let profiles = vec![
            store::LightProfile {
                id: "a".into(),
                name: "美国号".into(),
                account_uuid: Some("u-a".into()),
                email: None,
            },
            store::LightProfile {
                id: "b".into(),
                name: "日本号".into(),
                account_uuid: None,
                email: None,
            },
        ];
        let rows = account_menu_rows(&profiles, Some("a"));
        assert_eq!(
            rows[0],
            ("tray-switch-a".to_string(), "● 美国号".to_string())
        );
        assert_eq!(rows[1], ("tray-switch-b".to_string(), "日本号".to_string()));

        // 无 current 时不打 ●。
        let rows = account_menu_rows(&profiles, None);
        assert_eq!(rows[0].1, "美国号");
        assert_eq!(rows[1].0, "tray-switch-b");
        // 空列表 → 空行。
        assert!(account_menu_rows(&[], None).is_empty());
    }
}
