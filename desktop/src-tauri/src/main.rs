// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `smcp-desktop --commands`: where the bundled Gateway commands are and
    // the version each reports, for the installer smoke tests (FR-20.17,
    // FR-20.19). Exits before any window or tray is created.
    if std::env::args().nth(1).as_deref() == Some("--commands") {
        std::process::exit(smcp_desktop::commands::print_report());
    }
    smcp_desktop::run();
}
