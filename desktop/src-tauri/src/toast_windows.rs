//! Approval notifications on Windows (FR-20.7, SR-2.6-2): a toast with the
//! fixed text of `notify`, whose activation opens the console window at
//! the Approvals view. The toast has no buttons, input or reply field, so
//! its only action is that default one.
//!
//! The toast is protocol-activated with the link `smcp://approvals`
//! ([`crate::notify::toast_xml`]): a click, on the toast itself or later
//! in the notification center, makes Windows open that link, which the
//! `.msi` registers for the application. A running application receives
//! it through the single-instance handler (FR-20.28); one that has quit is
//! started with it. While the application runs, the toast's in-process
//! activation handler opens the view as well, which also covers a copy
//! run from a build directory, where the scheme is not registered.
//!
//! Windows shows a toast under an application user model ID. The
//! `smcp-desktop` `.msi` gives the Start menu shortcut the application's
//! identifier as that ID; a copy run from a build directory has no such
//! shortcut and uses the ID of Windows PowerShell, as
//! tauri-plugin-notification does.

use tauri_winrt_notification::Toast;
use windows::core::{IInspectable, HSTRING};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

/// The application user model ID for the toast.
pub fn app_id(identifier: &str, exe_dir: &std::path::Path) -> String {
    let d = exe_dir.to_string_lossy().to_ascii_lowercase();
    if d.ends_with("\\target\\debug") || d.ends_with("\\target\\release") {
        Toast::POWERSHELL_APP_ID.to_string()
    } else {
        identifier.to_string()
    }
}

/// Shows the toast; `on_open` runs when the user activates it while the
/// application runs.
pub fn show(app_id: &str, title: &str, body: &str, on_open: impl Fn() + Send + 'static) -> Result<(), String> {
    let doc = XmlDocument::new().map_err(|e| e.to_string())?;
    doc.LoadXml(&HSTRING::from(crate::notify::toast_xml(title, body)))
        .map_err(|e| e.to_string())?;
    let toast = ToastNotification::CreateToastNotification(&doc).map_err(|e| e.to_string())?;
    toast
        .Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(
            move |_, _| {
                on_open();
                Ok(())
            },
        ))
        .map_err(|e| e.to_string())?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id))
        .and_then(|n| n.Show(&toast))
        .map_err(|e| e.to_string())
}
