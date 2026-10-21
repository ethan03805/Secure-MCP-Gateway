// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // `smcp-desktop --commands`: where the bundled Gateway commands are and
    // the version each reports, for the installer smoke tests (FR-20.17,
    // FR-20.19). Exits before any window or tray is created.
    if std::env::args().nth(1).as_deref() == Some("--commands") {
        std::process::exit(smcp_desktop::commands::print_report());
    }
    // `smcp-desktop --setup-profiles`: the profiles first-run setup offers
    // on this host and the smcpctl it runs, for the installer smoke tests
    // (FR-20.19: an AppImage offers Standalone only). Runs nothing.
    if std::env::args().nth(1).as_deref() == Some("--setup-profiles") {
        std::process::exit(smcp_desktop::setup::print_report());
    }
    // `smcp-desktop --version`: the version the application was built with,
    // the one its update check compares with releases (FR-20.11, FR-20.13);
    // the installer smoke tests require the release's version.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", smcp_desktop::app_version());
        return;
    }
    smcp_desktop::run();
}
