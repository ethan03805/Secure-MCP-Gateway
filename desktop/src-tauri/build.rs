fn main() {
    // The application manifest lists every command, so each needs a
    // permission granted by a capability file (SR-2-5): without it Tauri
    // would allow application commands from every window, including the
    // console window.
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "get_settings",
            "save_settings",
            "intro_get",
            "intro_close",
            "intro_open_console",
            "intro_open_setup",
            "intro_open_client_setup",
            "intro_open_guide",
            "status_get",
            "status_open_console",
            "status_start",
            "status_restart",
        ])),
    )
    .expect("tauri-build failed");
}
