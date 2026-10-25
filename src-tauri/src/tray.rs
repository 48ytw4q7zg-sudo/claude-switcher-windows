//! 托盘图标、弹窗定位、刷新线程。

use std::sync::Mutex;
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::webview::PageLoadEvent;
use tauri::{
    AppHandle, Manager, PhysicalPosition, Position, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};

use crate::usage;

/// 弹窗逻辑尺寸（logical px），创建窗口与定位共用，不再两处硬编码。
const POPUP_WIDTH: f64 = 360.0;
const POPUP_HEIGHT: f64 = 410.0;

/// 弹窗因失焦隐藏后的防抖窗口：Windows 上点托盘图标会先让弹窗失焦隐藏，
/// 随后 Click 事件到达——没有防抖时 toggle 会把刚隐藏的弹窗又打开，
/// 表现为「点图标想关却关不掉」。
const POPUP_REOPEN_DEBOUNCE: StdDuration = StdDuration::from_millis(300);

static POPUP_HIDDEN_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// tooltip 预算：Windows 托盘约 127 字符；优先保留 5 小时与 7 天用量。
const TOOLTIP_MAX_CHARS: usize = 120;

pub fn refresh_tray_status(app: &tauri::AppHandle) -> Result<(), String> {
    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };
    let tray_usage = usage::claude_usage_snapshot()?;
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
    #[cfg(target_os = "macos")]
    tray.set_title(Some(String::new()))
        .map_err(|e| format!("更新菜单栏标题失败: {e}"))?;
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
    #[cfg(target_os = "macos")]
    let mut y = tray_position.y + 4.0 * scale;
    #[cfg(windows)]
    let mut y = tray_position.y - popup_h - 4.0 * scale;
    #[cfg(not(any(target_os = "macos", windows)))]
    let mut y = tray_position.y + 4.0 * scale;

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
        Err(error) => eprintln!("[claude-switcher] 创建托盘弹窗失败: {error}"),
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

/// 构建托盘右键菜单（打开主窗 / 刷新用量 / 退出）。
/// best-effort：任一构造步骤失败都返回 Err，由调用方打日志，不影响托盘本体。
fn build_tray_menu<R: tauri::Runtime>(
    app: &AppHandle<R>,
    tray: &tauri::tray::TrayIcon<R>,
) -> Result<(), String> {
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
    let menu = tauri::menu::Menu::with_items(app, &[&open_item, &refresh_item, &quit_item])
        .map_err(|e| format!("组装菜单失败: {e}"))?;
    tray.set_menu(Some(menu))
        .map_err(|e| format!("挂载菜单失败: {e}"))
}

/// 供调用方直接把 `tray_by_id` 的返回值（按值）传进来的重载。
fn build_tray_menu_owned<R: tauri::Runtime>(
    app: &AppHandle<R>,
    tray: tauri::tray::TrayIcon<R>,
) -> Result<(), String> {
    build_tray_menu(app, &tray)
}

pub fn install_tray_handlers(app: &mut tauri::App) -> Result<(), String> {
    let app_handle = app.handle().clone();
    if let Some(tray) = app_handle.tray_by_id("main") {
        #[cfg(target_os = "macos")]
        let _ = tray.set_title(Some(String::new()));
        let _ = tray.set_tooltip(Some("Claude Switcher".to_string()));
        // Windows：tauri.conf.json 里的 tray.png 是 macOS 单色模板图标，
        // 在深色任务栏上看不清。改用多尺寸彩色 ICO（16/24/32/48/64/256），
        // 高 DPI 与不同任务栏尺寸下都清晰。
        #[cfg(windows)]
        if let Ok(icon) = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.ico")) {
            let _ = tray.set_icon(Some(icon));
        }

        // Windows 习惯：右键托盘出菜单（打开主窗 / 刷新 / 退出）。
        // 菜单构建失败不阻断托盘初始化（托盘本体已经可用），只打日志。
        if let Err(error) = build_tray_menu_owned(&app_handle, tray) {
            eprintln!("[claude-switcher] 构建托盘菜单失败: {error}");
        }
    }

    let refresh_handle = app_handle.clone();
    thread::spawn(move || {
        let _ = refresh_tray_status(&refresh_handle);
        loop {
            thread::sleep(StdDuration::from_secs(60));
            let _ = refresh_tray_status(&refresh_handle);
        }
    });

    app.on_tray_icon_event(|app, event| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            position,
            ..
        } = event
        {
            toggle_tray_popup(app, position);
        }
    });

    app.on_menu_event(|app, event| match event.id().as_ref() {
        "tray-open" => show_main_window(app),
        "tray-refresh" => {
            let handle = app.clone();
            thread::spawn(move || {
                let _ = refresh_tray_status(&handle);
            });
        }
        "tray-quit" => quit_app(app),
        _ => {}
    });

    Ok(())
}
