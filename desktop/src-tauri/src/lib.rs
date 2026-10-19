//! Secure MCP Gateway desktop application (E-34, SRS FR-20).
//!
//! A tray application that holds no authority beyond the user's console
//! sign-in (SR-2-3): it reads the unauthenticated loopback metrics endpoint
//! for the tray state and the pending-approval count, controls the `smcpd`
//! service through the platform service manager, and shows the console
//! that `smcpd` serves in a window with no IPC access. It never reads the
//! Gateway configuration, the operator token, the Secret Vault, the key store or
//! the journal, and sends no request to the control API itself.
//!
//! The pure parts (state, metrics parsing, service commands, navigation
//! policy, certificate check, notification text, settings) are in their
//! own modules with unit tests; this file wires them to Tauri.

pub mod console;
pub mod health;
pub mod icons;
pub mod notify;
pub mod service;
pub mod settings;
pub mod state;
pub mod tlspin;

#[cfg(target_os = "linux")]
mod tlshook_linux;
#[cfg(target_os = "macos")]
mod tlshook_macos;

#[cfg(test)]
mod claims;
#[cfg(test)]
mod config_tests;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager as _, RunEvent, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

use crate::console::{Navigation, Page, CONSOLE_LABEL, WINDOW};
use crate::service::{Action, Host, Manager, SystemRunner};
use crate::settings::{FieldError, Resolved, Settings};
use crate::state::{Monitor, ServiceStatus, TrayState, TrayView};

/// The only bundled window that has commands (capabilities/settings.json).
pub const SETTINGS_LABEL: &str = "settings";
const TRAY_ID: &str = "smcp";

struct Items {
    approvals: MenuItem<tauri::Wry>,
    start: MenuItem<tauri::Wry>,
    stop: MenuItem<tauri::Wry>,
    restart: MenuItem<tauri::Wry>,
}

struct Shared {
    settings_path: PathBuf,
    settings: Mutex<Settings>,
    host: Host,
    xdg_state_home: Option<PathBuf>,
    service: Mutex<ServiceStatus>,
    items: Mutex<Option<Items>>,
    tray: Mutex<Option<TrayIcon>>,
}

impl Shared {
    fn resolved(&self) -> Result<Resolved, Vec<FieldError>> {
        let s = self.settings.lock().unwrap_or_else(|e| e.into_inner()).clone();
        s.resolve(self.host.os, &self.host.home, self.xdg_state_home.as_deref())
    }

    fn manager(&self) -> Option<Manager> {
        service::detect(&self.host)
    }
}

/// The settings window's view of the settings.
#[derive(serde::Serialize)]
struct SettingsView {
    settings: Settings,
    default_ca_file: String,
}

fn only_settings_window(w: &tauri::Webview) -> Result<(), String> {
    // Defence in depth beside the capability file (SR-2-5).
    if w.label() == SETTINGS_LABEL {
        Ok(())
    } else {
        Err("not allowed from this window".into())
    }
}

#[tauri::command]
fn get_settings(webview: tauri::Webview, shared: State<'_, Arc<Shared>>) -> Result<SettingsView, String> {
    only_settings_window(&webview)?;
    let s = shared.settings.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let default_ca_file =
        settings::default_ca_file(shared.host.os, &shared.host.home, shared.xdg_state_home.as_deref());
    Ok(SettingsView {
        settings: s,
        default_ca_file: default_ca_file.display().to_string(),
    })
}

#[tauri::command]
fn save_settings(
    app: AppHandle,
    webview: tauri::Webview,
    shared: State<'_, Arc<Shared>>,
    settings: Settings,
) -> Result<(), Vec<FieldError>> {
    only_settings_window(&webview).map_err(|m| {
        vec![FieldError {
            field: "window",
            message: m,
        }]
    })?;
    settings.resolve(shared.host.os, &shared.host.home, shared.xdg_state_home.as_deref())?;
    settings.save(&shared.settings_path).map_err(|e| {
        vec![FieldError {
            field: "file",
            message: e.to_string(),
        }]
    })?;
    let origin_changed = {
        let mut cur = shared.settings.lock().unwrap_or_else(|e| e.into_inner());
        let changed = cur.admin_url != settings.admin_url || cur.ca_file != settings.ca_file;
        *cur = settings;
        changed
    };
    if origin_changed {
        // The console window is bound to one origin and one CA; reopen it.
        if let Some(w) = app.get_webview_window(CONSOLE_LABEL) {
            let _ = w.close();
        }
    }
    Ok(())
}

fn notify(app: &AppHandle, body: &str) {
    let _ = app.notification().builder().title(notify::TITLE).body(body).show();
}

fn open_settings(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(SETTINGS_LABEL) {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, SETTINGS_LABEL, WebviewUrl::App("settings.html".into()))
        .title("Secure MCP Gateway Settings")
        .inner_size(560.0, 520.0)
        .resizable(false)
        .build();
}

/// Shows the console window at `page`, creating it if needed (FR-20.6).
fn open_console(app: &AppHandle, page: Page) {
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let r = match shared.resolved() {
        Ok(r) => r,
        Err(_) => {
            open_settings(app);
            return;
        }
    };
    let target = r.admin.page(page.path());
    if let Some(w) = app.get_webview_window(CONSOLE_LABEL) {
        if page != Page::Home {
            let _ = w.navigate(target);
        }
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let anchors = std::fs::read(&r.ca_file)
        .map_err(|e| tlspin::PinError::NoAnchors(format!("{}: {e}", r.ca_file.display())))
        .and_then(|b| tlspin::parse_ca_bundle(&b));
    let admin = r.admin.clone();
    let admin2 = r.admin.clone();
    let built = WebviewWindowBuilder::new(
        app,
        CONSOLE_LABEL,
        WebviewUrl::External("about:blank".parse().expect("valid")),
    )
    .title(WINDOW.title)
    .inner_size(WINDOW.width, WINDOW.height)
    .incognito(WINDOW.incognito)
    .devtools(WINDOW.devtools)
    .on_navigation(move |u| match console::decide(u, &admin) {
        Navigation::Allow => true,
        Navigation::OpenInBrowser => {
            let _ = tauri_plugin_opener::open_url(u.as_str(), None::<&str>);
            false
        }
        Navigation::Refuse => false,
    })
    .on_new_window(move |u, _| {
        if console::decide(&u, &admin2) != Navigation::Refuse {
            let _ = tauri_plugin_opener::open_url(u.as_str(), None::<&str>);
        }
        NewWindowResponse::Deny
    })
    .build();
    let Ok(w) = built else { return };
    let refused = {
        let app = app.clone();
        move |reason: String| {
            eprintln!("smcp-desktop: console refused: {reason}");
            if let Some(w) = app.get_webview_window(CONSOLE_LABEL) {
                let _ = w.set_title(&format!("{} - not opened: {reason}", WINDOW.title));
                let _ = w.navigate(console::error_page());
            }
        }
    };
    let w2 = w.clone();
    let _ = w.with_webview(move |pw| {
        #[cfg(target_os = "macos")]
        {
            let _ = &pw;
            tlshook_macos::on_refused(refused.clone());
            tlshook_macos::set_pin(tlshook_macos::Pin {
                host: r.admin.host.clone(),
                port: r.admin.port,
                anchors,
            });
            // SAFETY: with_webview runs on the main thread with a live WKWebView.
            match unsafe { tlshook_macos::install(pw.inner()) } {
                Ok(()) => {
                    let _ = w2.navigate(target);
                }
                Err(e) => refused(e),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let pin = tlshook_linux::Pin {
                host: r.admin.host.clone(),
                port: r.admin.port,
                anchors,
            };
            tlshook_linux::install(&pw.inner(), pin, refused);
            let _ = w2.navigate(target);
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            // No certificate hook on this platform yet: fail closed.
            let _ = (&pw, &anchors, &target, &w2);
            refused("the console window is not supported on this platform yet".into());
        }
    });
}

fn run_action(app: &AppHandle, action: Action) {
    let app = app.clone();
    std::thread::spawn(move || {
        let shared = app.state::<Arc<Shared>>().inner().clone();
        let msg = match service::perform(&SystemRunner, shared.manager().as_ref(), action) {
            Ok(m) | Err(m) => m,
        };
        notify(&app, &msg);
    });
}

fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "open_console" => open_console(app, Page::Home),
        "approvals" => open_console(app, Page::Approvals),
        "start" => run_action(app, Action::Start),
        "stop" => run_action(app, Action::Stop),
        "restart" => run_action(app, Action::Restart),
        "settings" => open_settings(app),
        "quit" => app.exit(0),
        _ => {}
    }
}

fn build_tray(app: &AppHandle, shared: &Arc<Shared>) -> tauri::Result<()> {
    let item = |id: &str, text: &str, enabled: bool| MenuItem::with_id(app, id, text, enabled, None::<&str>);
    let open = item("open_console", "Open Console", true)?;
    let approvals = item("approvals", "Approvals", true)?;
    let start = item("start", "Start", false)?;
    let stop = item("stop", "Stop", false)?;
    let restart = item("restart", "Restart", false)?;
    // Set Up a Client and Check for Updates arrive with the client-setup
    // and update windows (FR-20.10, FR-20.11); until then they are shown
    // disabled so the menu has the FR-20.2 shape.
    let setup = item("setup_client", "Set Up a Client", false)?;
    let updates = item("check_updates", "Check for Updates", false)?;
    let settings_item = item("settings", "Settings…", true)?;
    let quit = item("quit", "Quit", true)?;
    let sep = || PredefinedMenuItem::separator(app);
    let menu = Menu::with_items(
        app,
        &[
            &open,
            &approvals,
            &sep()?,
            &start,
            &stop,
            &restart,
            &sep()?,
            &setup,
            &updates,
            &settings_item,
            &sep()?,
            &quit,
        ],
    )?;
    let view = TrayView {
        state: TrayState::Unreachable,
        not_enforced: true,
        pending: None,
    };
    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(Image::new_owned(icons::rgba(view.state), icons::SIZE, icons::SIZE))
        .tooltip(view.accessible_name())
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, ev| on_menu(app, ev.id().as_ref()))
        .build(app)?;
    *shared.items.lock().unwrap_or_else(|e| e.into_inner()) = Some(Items {
        approvals,
        start,
        stop,
        restart,
    });
    *shared.tray.lock().unwrap_or_else(|e| e.into_inner()) = Some(tray);
    Ok(())
}

fn show(shared: &Shared, view: &TrayView, service: ServiceStatus) {
    if let Some(tray) = shared.tray.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        let _ = tray.set_icon(Some(Image::new_owned(
            icons::rgba(view.state),
            icons::SIZE,
            icons::SIZE,
        )));
        let _ = tray.set_tooltip(Some(view.accessible_name()));
        let label = view.label();
        let _ = tray.set_title(if label.is_empty() { None } else { Some(label) });
    }
    if let Some(items) = shared.items.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        let e = state::service_items(service);
        let _ = items.start.set_enabled(e.start);
        let _ = items.stop.set_enabled(e.stop);
        let _ = items.restart.set_enabled(e.restart);
        let text = match view.pending {
            Some(n) => format!("Approvals ({n} pending)"),
            None => "Approvals".to_string(),
        };
        let _ = items.approvals.set_text(text);
    }
}

/// Reads the metrics endpoint and the service manager every
/// POLL_INTERVAL and updates the tray (FR-20.4) and notifications (FR-20.7).
fn poll(app: AppHandle, shared: Arc<Shared>) {
    let mut monitor = Monitor::default();
    let mut notifier = notify::Notifier::default();
    let mut last: Option<(TrayView, ServiceStatus)> = None;
    loop {
        let started = Instant::now();
        let service_status = service::status(&SystemRunner, shared.manager().as_ref());
        *shared.service.lock().unwrap_or_else(|e| e.into_inner()) = service_status;
        let resolved = shared.resolved();
        match resolved
            .as_ref()
            .map_err(|_| ())
            .and_then(|r| health::read(r.metrics, Duration::from_secs(2)).map_err(|_| ()))
        {
            Ok(e) => monitor.record_ok(Instant::now(), e),
            Err(()) => monitor.record_failure(),
        }
        let view = monitor.view(Instant::now(), service_status);
        if let Some(n) = view.pending {
            let enabled = resolved.as_ref().map(|r| r.notifications).unwrap_or(false);
            if let Some(notice) = notifier.observe(n, enabled) {
                notify(&app, &notice.body);
            }
        }
        if last.as_ref() != Some(&(view.clone(), service_status)) {
            eprintln!(
                "smcp-desktop: tray: {} (service {service_status:?})",
                view.accessible_name()
            );
            show(&shared, &view, service_status);
            last = Some((view, service_status));
        }
        std::thread::sleep(state::POLL_INTERVAL.saturating_sub(started.elapsed()));
    }
}

/// Runs the application.
pub fn run() {
    let context = tauri::generate_context!();
    let app = tauri::Builder::default()
        // First, so a second start only focuses the first (FR-20.14).
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            open_console(app, Page::Home)
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![get_settings, save_settings])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let dir = app.path().app_config_dir()?;
            let settings_path = dir.join("settings.json");
            let shared = Arc::new(Shared {
                settings: Mutex::new(Settings::load(&settings_path)),
                settings_path,
                host: Host::current(),
                xdg_state_home: std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
                service: Mutex::new(ServiceStatus::Unknown),
                items: Mutex::new(None),
                tray: Mutex::new(None),
            });
            app.manage(shared.clone());
            build_tray(app.handle(), &shared)?;
            let handle = app.handle().clone();
            std::thread::spawn(move || poll(handle, shared));
            Ok(())
        })
        .build(context)
        .expect("error while building the desktop application");
    app.run(|_app, ev| {
        // Closing the last window keeps the tray running; Quit exits.
        if let RunEvent::ExitRequested { api, code, .. } = ev {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
