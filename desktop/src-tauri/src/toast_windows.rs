//! Approval notifications on Windows (FR-20.7, SR-2.6-2): a toast with the
//! fixed text of `notify`, whose activation opens the console window at
//! the Approvals view. The toast has no buttons, input or reply field, so
//! its only action is that default one.
//!
//! Windows shows a toast under an application user model ID. The
//! `smcp-desktop` `.msi` gives the Start menu shortcut the application's
//! identifier as that ID; a copy run from a build directory has no such
//! shortcut and uses the ID of Windows PowerShell, as
//! tauri-plugin-notification does.

use tauri_winrt_notification::Toast;

/// The application user model ID for the toast.
pub fn app_id(identifier: &str, exe_dir: &std::path::Path) -> String {
    let d = exe_dir.to_string_lossy().to_ascii_lowercase();
    if d.ends_with("\\target\\debug") || d.ends_with("\\target\\release") {
        Toast::POWERSHELL_APP_ID.to_string()
    } else {
        identifier.to_string()
    }
}

/// Shows the toast; `on_open` runs when the user activates it.
pub fn show(app_id: &str, title: &str, body: &str, on_open: impl Fn() + Send + 'static) -> Result<(), String> {
    Toast::new(app_id)
        .title(title)
        .text1(body)
        .on_activated(move |_| {
            on_open();
            Ok(())
        })
        .show()
        .map_err(|e| e.to_string())
}
