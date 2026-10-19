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

pub mod clients;
pub mod console;
pub mod explain;
pub mod health;
pub mod icons;
pub mod intro;
pub mod notify;
pub mod service;
pub mod settings;
pub mod setup;
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
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager as _, RunEvent, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

use crate::console::{Navigation, Page, CONSOLE_LABEL, WINDOW};
use crate::service::{Action, Host, Manager, Runner as _, SystemRunner};
use crate::settings::{FieldError, Resolved, Settings};
use crate::state::{Monitor, ServiceStatus, TrayState, TrayView};

/// The bundled windows. Each has its own capability file granting only its
/// own commands (SR-2-5); the console window has none.
pub const SETTINGS_LABEL: &str = "settings";
pub const INTRO_LABEL: &str = "intro";
pub const STATUS_LABEL: &str = "status";
pub const SETUP_LABEL: &str = "setup";
pub const CLIENTS_LABEL: &str = "clients";
/// The desktop guide, opened in the default browser from Help.
const GUIDE_URL: &str = "https://github.com/ethan03805/Secure-MCP-Gateway/blob/main/docs/desktop.md";
/// Where the introduction sends a user for a task this version of the
/// application cannot do itself yet (first-run setup, client setup).
const GUIDE_SETUP_URL: &str = "https://github.com/ethan03805/Secure-MCP-Gateway/blob/main/docs/install.md";
const GUIDE_CONNECT_URL: &str = "https://github.com/ethan03805/Secure-MCP-Gateway/blob/main/docs/quickstart.md";
const TRAY_ID: &str = "smcp";

struct Items {
    status_title: MenuItem<tauri::Wry>,
    status_line: MenuItem<tauri::Wry>,
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
    /// The application's configuration directory (settings, introduction flag).
    config_dir: PathBuf,
    /// The latest tray view and when the metrics were last read, for the
    /// Gateway Status window.
    view: Mutex<Option<TrayView>>,
    last_read: Mutex<Option<Instant>>,
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

fn only_window(w: &tauri::Webview, label: &str) -> Result<(), String> {
    // Defence in depth beside the capability files (SR-2-5).
    if w.label() == label {
        Ok(())
    } else {
        Err("not allowed from this window".into())
    }
}

/// What the Introduction window may offer (FR-20.40). First-run setup and
/// client setup arrive with their windows (FR-20.8, FR-20.10); until then
/// the introduction points to the guide for those two tasks.
#[derive(serde::Serialize)]
struct IntroInfo {
    available: Vec<&'static str>,
}

#[tauri::command]
fn intro_get(webview: tauri::Webview) -> Result<IntroInfo, String> {
    only_window(&webview, INTRO_LABEL)?;
    Ok(IntroInfo {
        available: vec!["setup", "client-setup", "open-console"],
    })
}

/// Stores how the user left the introduction and closes it (FR-20.41);
/// first-run setup follows when the Gateway is not set up (FR-20.40).
#[tauri::command]
fn intro_close(webview: tauri::Webview, shared: State<'_, Arc<Shared>>, flag: String) -> Result<(), String> {
    only_window(&webview, INTRO_LABEL)?;
    let flag = intro::Flag::parse(&flag).ok_or("unknown introduction flag")?;
    let saved = intro::save(&shared.config_dir, flag).map_err(|e| e.to_string());
    if let Some(w) = webview.app_handle().get_webview_window(INTRO_LABEL) {
        let _ = w.close();
    }
    if !setup::configured(&shared.host) {
        open_setup(webview.app_handle());
    }
    saved
}

#[tauri::command]
fn intro_open_console(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, INTRO_LABEL)?;
    open_console(&app, Page::Home);
    Ok(())
}

#[tauri::command]
fn intro_open_setup(webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, INTRO_LABEL)?;
    open_setup(webview.app_handle());
    Ok(())
}

#[tauri::command]
fn intro_open_client_setup(webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, INTRO_LABEL)?;
    open_clients(webview.app_handle());
    Ok(())
}

/// Opens a fixed guide page in the default browser; the window names only
/// the topic, never an address.
#[tauri::command]
fn intro_open_guide(webview: tauri::Webview, topic: String) -> Result<(), String> {
    only_window(&webview, INTRO_LABEL)?;
    let url = match topic.as_str() {
        "setup" => GUIDE_SETUP_URL,
        "connect" => GUIDE_CONNECT_URL,
        _ => return Err("unknown guide topic".into()),
    };
    tauri_plugin_opener::open_url(url, None::<&str>).map_err(|e| e.to_string())
}

/// The Gateway Status window's reading (FR-20.45).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusReading {
    state: &'static str,
    enforced: bool,
    last_reading: Option<String>,
    pending: Option<u64>,
}

#[tauri::command]
fn status_get(webview: tauri::Webview, shared: State<'_, Arc<Shared>>) -> Result<StatusReading, String> {
    only_window(&webview, STATUS_LABEL)?;
    let view = shared
        .view
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or(TrayView {
            state: TrayState::Unreachable,
            not_enforced: true,
            pending: None,
        });
    let last = *shared.last_read.lock().unwrap_or_else(|e| e.into_inner());
    Ok(StatusReading {
        state: explain::key(view.state),
        enforced: !view.not_enforced,
        last_reading: last.map(|t| format!("{} seconds ago", t.elapsed().as_secs())),
        pending: view.pending,
    })
}

#[tauri::command]
fn status_open_console(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, STATUS_LABEL)?;
    open_console(&app, Page::Home);
    Ok(())
}

#[tauri::command]
fn status_start(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, STATUS_LABEL)?;
    run_action(&app, Action::Start);
    Ok(())
}

#[tauri::command]
fn status_restart(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, STATUS_LABEL)?;
    run_action(&app, Action::Restart);
    Ok(())
}

/// What the setup window needs to offer the profiles (FR-20.8, FR-20.9).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupInfo {
    os: &'static str,
    configured: bool,
    smcpctl: Option<String>,
    profiles: Vec<ProfileInfo>,
    progress: setup::Progress,
}

#[derive(serde::Serialize)]
struct ProfileInfo {
    id: setup::Profile,
    /// The prerequisite check (Enforced on Linux only); none means offered.
    check: Option<setup::Check>,
}

/// A refused setup request, by message-catalogue code.
#[derive(serde::Serialize)]
struct SetupRefusal {
    code: &'static str,
    role: Option<&'static str>,
}

fn refusal(code: &'static str) -> Vec<SetupRefusal> {
    vec![SetupRefusal { code, role: None }]
}

fn smcpctl_path(host: &Host) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok();
    setup::find_smcpctl(exe.as_deref().and_then(std::path::Path::parent), host)
}

fn appimage() -> bool {
    std::env::var_os("APPIMAGE").is_some()
}

/// Reads whether the Gateway is set up and, on Linux, runs the Enforced
/// prerequisite check before the window offers that profile (FR-20.9).
#[tauri::command]
async fn setup_get(app: AppHandle, webview: tauri::Webview) -> Result<SetupInfo, String> {
    only_window(&webview, SETUP_LABEL)?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<setup::Session>>().inner().clone();
    let smcpctl = smcpctl_path(&shared.host);
    let mut profiles = Vec::new();
    for id in setup::profiles(shared.host.os, appimage()) {
        let check = match (id, smcpctl.as_deref()) {
            (setup::Profile::Standalone, _) => None,
            (setup::Profile::Enforced, None) => Some(setup::Check::Failed {
                detail: "smcpctl was not found".into(),
            }),
            (setup::Profile::Enforced, Some(p)) => {
                let argv = setup::check_argv(p);
                let r = tauri::async_runtime::spawn_blocking(move || SystemRunner.run(&argv, setup::CHECK_TIMEOUT))
                    .await
                    .map_err(|e| e.to_string())?;
                let c = setup::parse_check(&r);
                *session.enforced.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.clone());
                Some(c)
            }
        };
        profiles.push(ProfileInfo { id, check });
    }
    let progress = session.progress.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(SetupInfo {
        os: shared.host.os,
        configured: setup::configured(&shared.host),
        smcpctl: smcpctl.map(|p| p.display().to_string()),
        profiles,
        progress,
    })
}

/// Starts the installation (FR-20.8). The passwords go only into the two
/// private files the session deletes when `smcpctl` ends.
#[tauri::command]
fn setup_run(
    app: AppHandle,
    webview: tauri::Webview,
    profile: setup::Profile,
    admin: setup::Secret,
    approver: setup::Secret,
) -> Result<(), Vec<SetupRefusal>> {
    only_window(&webview, SETUP_LABEL).map_err(|_| refusal("SETUP_NOT_ALLOWED"))?;
    setup::validate(&admin, &approver).map_err(|errs| {
        errs.into_iter()
            .map(|e| SetupRefusal {
                code: e.code,
                role: Some(e.role),
            })
            .collect::<Vec<_>>()
    })?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<setup::Session>>().inner().clone();
    if setup::configured(&shared.host) {
        return Err(refusal("SETUP_ALREADY_CONFIGURED"));
    }
    let checked = *session.enforced.lock().unwrap_or_else(|e| e.into_inner()) == Some(setup::Check::Present);
    if !setup::profiles(shared.host.os, appimage()).contains(&profile)
        || (profile == setup::Profile::Enforced && !checked)
    {
        return Err(refusal("SETUP_PROFILE_UNAVAILABLE"));
    }
    let smcpctl = smcpctl_path(&shared.host).ok_or_else(|| refusal("SETUP_SMCPCTL_MISSING"))?;
    if !session.begin(profile) {
        return Err(refusal("SETUP_RUNNING"));
    }
    std::thread::spawn(move || {
        session.execute(&smcpctl, profile, admin, approver, &std::env::temp_dir());
    });
    Ok(())
}

#[tauri::command]
fn setup_progress(webview: tauri::Webview, session: State<'_, Arc<setup::Session>>) -> Result<setup::Progress, String> {
    only_window(&webview, SETUP_LABEL)?;
    Ok(session.progress.lock().unwrap_or_else(|e| e.into_inner()).clone())
}

#[tauri::command]
fn setup_open_console(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, SETUP_LABEL)?;
    open_console(&app, Page::Home);
    Ok(())
}

#[tauri::command]
fn setup_open_client_setup(app: AppHandle, webview: tauri::Webview) -> Result<(), String> {
    only_window(&webview, SETUP_LABEL)?;
    open_clients(&app);
    Ok(())
}

/// What the client setup window lists (FR-20.10, FR-20.46).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ClientsView {
    /// A Gateway configuration exists, so `smcpctl connect` can run.
    gateway_set_up: bool,
    smcpctl: bool,
    clients: Vec<clients::Client>,
    /// Why detection failed, when it did.
    failure: Option<clients::Outcome>,
}

/// The paths client setup needs, or the catalogue code of what is missing.
fn clients_paths(shared: &Shared) -> Result<(PathBuf, PathBuf), &'static str> {
    let smcpctl = smcpctl_path(&shared.host).ok_or("SETUP_SMCPCTL_MISSING")?;
    let cfg = clients::config_path(&shared.host).ok_or("CLIENTS_GATEWAY_NOT_SET_UP")?;
    Ok((smcpctl, cfg))
}

fn refused_outcome(code: &'static str) -> clients::Outcome {
    clients::Outcome {
        code: Some(code),
        ..Default::default()
    }
}

#[tauri::command]
async fn clients_list(app: AppHandle, webview: tauri::Webview) -> Result<ClientsView, String> {
    only_window(&webview, CLIENTS_LABEL)?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<clients::Session>>().inner().clone();
    let smcpctl = smcpctl_path(&shared.host);
    let mut view = ClientsView {
        gateway_set_up: clients::config_path(&shared.host).is_some(),
        smcpctl: smcpctl.is_some(),
        clients: Vec::new(),
        failure: None,
    };
    let Some(smcpctl) = smcpctl else { return Ok(view) };
    let argv = clients::detect_argv(&smcpctl);
    let home = shared.host.home.clone();
    let a = argv.clone();
    let (exit, out) = tauri::async_runtime::spawn_blocking(move || clients::run(&a, &home))
        .await
        .map_err(|e| e.to_string())?;
    match clients::parse_detect(&out).filter(|_| exit.code == Some(0)) {
        Some(list) => {
            *session.known.lock().unwrap_or_else(|e| e.into_inner()) = list.iter().map(|c| c.id.clone()).collect();
            view.clients = list;
        }
        None => view.failure = Some(clients::outcome(&argv, &exit, out, "CLIENTS_DETECT_FAILED")),
    }
    Ok(view)
}

/// Shows the changes `smcpctl connect <client> --dry-run` reports; nothing
/// is written (FR-20.10).
#[tauri::command]
async fn clients_preview(
    app: AppHandle,
    webview: tauri::Webview,
    id: String,
    lockdown: bool,
) -> Result<clients::Preview, clients::Outcome> {
    only_window(&webview, CLIENTS_LABEL).map_err(|_| refused_outcome("SETUP_NOT_ALLOWED"))?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<clients::Session>>().inner().clone();
    if !session.is_known(&id) {
        return Err(refused_outcome("CLIENT_UNKNOWN"));
    }
    let (smcpctl, cfg) = clients_paths(&shared).map_err(refused_outcome)?;
    let argv = clients::preview_argv(&smcpctl, &cfg, &id, lockdown);
    let home = shared.host.home.clone();
    let a = argv.clone();
    let (exit, out) = tauri::async_runtime::spawn_blocking(move || clients::run(&a, &home))
        .await
        .map_err(|_| refused_outcome("CLIENT_PREVIEW_FAILED"))?;
    match clients::parse_preview(&out).filter(|p| exit.code == Some(0) && p.client == id) {
        Some(p) => {
            *session.previewed.lock().unwrap_or_else(|e| e.into_inner()) = Some((id, lockdown));
            Ok(p)
        }
        None => Err(clients::outcome(&argv, &exit, out, "CLIENT_PREVIEW_FAILED")),
    }
}

/// Applies the setup the user confirmed, only if it is the one previewed.
#[tauri::command]
async fn clients_apply(
    app: AppHandle,
    webview: tauri::Webview,
    id: String,
    lockdown: bool,
) -> Result<clients::Outcome, String> {
    only_window(&webview, CLIENTS_LABEL)?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<clients::Session>>().inner().clone();
    if !session.is_known(&id) || !session.was_previewed(&id, lockdown) {
        return Ok(refused_outcome("CLIENT_NOT_PREVIEWED"));
    }
    let (smcpctl, cfg) = match clients_paths(&shared) {
        Ok(p) => p,
        Err(code) => return Ok(refused_outcome(code)),
    };
    *session.previewed.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let argv = clients::apply_argv(&smcpctl, &cfg, &id, lockdown);
    let home = shared.host.home.clone();
    let a = argv.clone();
    let (exit, out) = tauri::async_runtime::spawn_blocking(move || clients::run(&a, &home))
        .await
        .map_err(|e| e.to_string())?;
    Ok(clients::outcome(&argv, &exit, out, "CLIENT_SETUP_FAILED"))
}

/// Restores the client's files (`--remove`, FR-20.10).
#[tauri::command]
async fn clients_remove(app: AppHandle, webview: tauri::Webview, id: String) -> Result<clients::Outcome, String> {
    only_window(&webview, CLIENTS_LABEL)?;
    let shared = app.state::<Arc<Shared>>().inner().clone();
    let session = app.state::<Arc<clients::Session>>().inner().clone();
    if !session.is_known(&id) {
        return Ok(refused_outcome("CLIENT_UNKNOWN"));
    }
    let (smcpctl, cfg) = match clients_paths(&shared) {
        Ok(p) => p,
        Err(code) => return Ok(refused_outcome(code)),
    };
    let argv = clients::remove_argv(&smcpctl, &cfg, &id);
    let home = shared.host.home.clone();
    let a = argv.clone();
    let (exit, out) = tauri::async_runtime::spawn_blocking(move || clients::run(&a, &home))
        .await
        .map_err(|e| e.to_string())?;
    Ok(clients::outcome(&argv, &exit, out, "CLIENT_REMOVE_FAILED"))
}

/// Shows a bundled window, creating it if needed.
fn open_bundled(app: &AppHandle, label: &str, page: &str, title: &str, size: (f64, f64)) {
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let _ = WebviewWindowBuilder::new(app, label, WebviewUrl::App(page.into()))
        .title(title)
        .inner_size(size.0, size.1)
        .resizable(false)
        .build();
}

/// The first-run introduction (FR-20.40), at the first start and from Help.
fn open_intro(app: &AppHandle) {
    open_bundled(app, INTRO_LABEL, "intro.html", "Introduction", (600.0, 560.0));
}

/// First-run setup (FR-20.8): after the introduction, at start while the
/// Gateway is not set up, and from Help.
fn open_setup(app: &AppHandle) {
    open_bundled(app, SETUP_LABEL, "setup.html", "Set Up the Gateway", (640.0, 640.0));
}

/// Client setup (FR-20.10), from the tray's Set Up a Client, the
/// introduction and the end of first-run setup.
fn open_clients(app: &AppHandle) {
    open_bundled(app, CLIENTS_LABEL, "clients.html", "Set Up a Client", (720.0, 680.0));
}

/// The Gateway Status window (FR-20.45), from the tray's status lines.
fn open_status(app: &AppHandle) {
    open_bundled(app, STATUS_LABEL, "status.html", "Gateway Status", (600.0, 560.0));
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
        "status" | "help_status" => open_status(app),
        "help_intro" => open_intro(app),
        "help_setup" => open_setup(app),
        "setup_client" => open_clients(app),
        "help_guide" => {
            let _ = tauri_plugin_opener::open_url(GUIDE_URL, None::<&str>);
        }
        "quit" => app.exit(0),
        _ => {}
    }
}

fn build_tray(app: &AppHandle, shared: &Arc<Shared>) -> tauri::Result<()> {
    let item = |id: &str, text: &str, enabled: bool| MenuItem::with_id(app, id, text, enabled, None::<&str>);
    // Status lines (FR-20.45): the state and what it means; either opens
    // the Gateway Status window, which says what to do.
    let status_title = item("status", "Unreachable", true)?;
    let status_line = item("status", "", true)?;
    let open = item("open_console", "Open Console", true)?;
    let approvals = item("approvals", "Approvals", true)?;
    let start = item("start", "Start", false)?;
    let stop = item("stop", "Stop", false)?;
    let restart = item("restart", "Restart", false)?;
    // Check for Updates arrives with the update window (FR-20.11); until
    // then it is shown disabled so the menu has the FR-20.2 shape.
    let setup = item("setup_client", "Set Up a Client…", true)?;
    let updates = item("check_updates", "Check for Updates", false)?;
    let settings_item = item("settings", "Settings…", true)?;
    // Help (FR-20.41): the introduction, the status explanations and the guide.
    let help = Submenu::with_items(
        app,
        "Help",
        true,
        &[
            &item("help_intro", "Introduction", true)?,
            &item("help_setup", "Set Up the Gateway…", true)?,
            &item("help_status", "Gateway Status", true)?,
            &item("help_guide", "Desktop Guide", true)?,
        ],
    )?;
    let quit = item("quit", "Quit", true)?;
    let sep = || PredefinedMenuItem::separator(app);
    let menu = Menu::with_items(
        app,
        &[
            &status_title,
            &status_line,
            &sep()?,
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
            &help,
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
    let (title, line) = explain::status_lines(&view);
    let _ = status_title.set_text(title);
    let _ = status_line.set_text(line);
    *shared.items.lock().unwrap_or_else(|e| e.into_inner()) = Some(Items {
        status_title,
        status_line,
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
        let (title, line) = explain::status_lines(view);
        let _ = items.status_title.set_text(title);
        let _ = items.status_line.set_text(line);
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
            Ok(e) => {
                monitor.record_ok(Instant::now(), e);
                *shared.last_read.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            }
            Err(()) => monitor.record_failure(),
        }
        let view = monitor.view(Instant::now(), service_status);
        *shared.view.lock().unwrap_or_else(|e| e.into_inner()) = Some(view.clone());
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
        .invoke_handler(tauri::generate_handler![
            get_settings,
            save_settings,
            intro_get,
            intro_close,
            intro_open_console,
            intro_open_setup,
            intro_open_client_setup,
            intro_open_guide,
            status_get,
            status_open_console,
            status_start,
            status_restart,
            setup_get,
            setup_run,
            setup_progress,
            setup_open_console,
            setup_open_client_setup,
            clients_list,
            clients_preview,
            clients_apply,
            clients_remove
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let dir = app.path().app_config_dir()?;
            let settings_path = dir.join("settings.json");
            let show_intro = intro::show_at_start(intro::load(&dir));
            let shared = Arc::new(Shared {
                settings: Mutex::new(Settings::load(&settings_path)),
                settings_path,
                host: Host::current(),
                xdg_state_home: std::env::var_os("XDG_STATE_HOME").map(PathBuf::from),
                service: Mutex::new(ServiceStatus::Unknown),
                items: Mutex::new(None),
                tray: Mutex::new(None),
                config_dir: dir,
                view: Mutex::new(None),
                last_read: Mutex::new(None),
            });
            app.manage(shared.clone());
            app.manage(Arc::new(setup::Session::default()));
            app.manage(Arc::new(clients::Session::default()));
            build_tray(app.handle(), &shared)?;
            // FR-20.40: the introduction opens at the first start.
            if show_intro {
                open_intro(app.handle());
            } else if !setup::configured(&shared.host) {
                // FR-20.8: no Gateway configuration, so setup is offered.
                open_setup(app.handle());
            }
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
