//! Checks of the application's configuration files: the capability set is
//! minimal (SR-2-5), bundled pages load only packaged assets under a
//! `default-src 'self'` policy (SR-2-6), the updater and shell plugins are
//! absent (FR-20.13, SR-2-5), and the single-instance plugin is registered
//! first (FR-20.14).

use crate::claims;
use serde_json::Value;

const CONF: &str = include_str!("../tauri.conf.json");
const CARGO: &str = include_str!("../Cargo.toml");
const BUILD: &str = include_str!("../build.rs");
const LIB: &str = include_str!("lib.rs");
const CAPABILITY: &str = include_str!("../capabilities/settings.json");

fn conf() -> Value {
    serde_json::from_str(CONF).expect("tauri.conf.json is JSON")
}

/// SR-2-3: the application code (outside its tests) names no Gateway
/// secret, configuration file or control-API route. The only Gateway file
/// it reads is the public CA bundle `tls/ca.crt`; every console operation
/// happens in the console window under the user's own sign-in.
#[test]
fn no_gateway_secret_or_control_api_in_the_application() {
    claims::partial(&["SR-2-3"]);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if !name.ends_with(".rs") || name == "config_tests.rs" || name == "claims.rs" {
            continue;
        }
        // A Windows checkout may have CRLF line ends.
        let src = std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
        let code = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        // First-run setup checks whether a configuration file exists
        // (FR-20.8) and reads no file at all.
        let names_config = name == "setup.rs";
        if names_config {
            for read in ["fs::read", "read_to_string", "File::open", ".read(true)"] {
                assert!(!code.contains(read), "setup.rs reads a file ({read})");
            }
        }
        for needle in [
            "operator_token",
            "operator.token",
            "/admin/v1",
            "/api/v1",
            "smcp.toml",
            "vault",
            "journal/",
            "ca.key",
            "server.key",
            "password_hash",
            "Authorization",
        ] {
            if names_config && needle == "smcp.toml" {
                continue;
            }
            assert!(!code.contains(needle), "{name} mentions {needle}");
        }
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} source files checked");
}

/// Each bundled window has one capability granting only its own commands;
/// the console window has none (SR-2-5).
const CAPABILITIES: [(&str, &str, &str, &[&str]); 6] = [
    (
        "settings.json",
        "settings-window",
        "settings",
        &["allow-get-settings", "allow-save-settings"],
    ),
    (
        "intro.json",
        "intro-window",
        "intro",
        &[
            "allow-intro-get",
            "allow-intro-close",
            "allow-intro-open-console",
            "allow-intro-open-setup",
            "allow-intro-open-client-setup",
            "allow-intro-open-guide",
        ],
    ),
    (
        "status.json",
        "status-window",
        "status",
        &[
            "allow-status-get",
            "allow-status-open-console",
            "allow-status-start",
            "allow-status-restart",
        ],
    ),
    (
        "setup.json",
        "setup-window",
        "setup",
        &[
            "allow-setup-get",
            "allow-setup-run",
            "allow-setup-progress",
            "allow-setup-open-console",
            "allow-setup-open-client-setup",
        ],
    ),
    (
        "clients.json",
        "clients-window",
        "clients",
        &[
            "allow-clients-list",
            "allow-clients-preview",
            "allow-clients-apply",
            "allow-clients-remove",
        ],
    ),
    (
        "updates.json",
        "updates-window",
        "updates",
        &[
            "allow-updates-get",
            "allow-updates-check",
            "allow-updates-open-notes",
            "allow-updates-install-app",
            "allow-updates-upgrade-gateway",
        ],
    ),
];

#[test]
fn one_capability_per_bundled_window_and_none_for_the_console() {
    claims::partial(&["SR-2-5"]);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    let mut want: Vec<_> = CAPABILITIES.iter().map(|c| c.0.to_string()).collect();
    want.sort();
    assert_eq!(files, want, "unexpected capability files");
    for (file, id, window, perms) in CAPABILITIES {
        let cap: Value = serde_json::from_str(&std::fs::read_to_string(dir.join(file)).unwrap()).unwrap();
        assert_eq!(cap["identifier"], Value::from(id), "{file}");
        assert_eq!(cap["windows"], serde_json::json!([window]), "{file}");
        assert_ne!(window, crate::console::CONSOLE_LABEL);
        assert!(cap.get("webviews").is_none(), "{file}");
        assert!(cap.get("remote").is_none(), "{file} lists a remote URL");
        assert_ne!(cap["local"], Value::Bool(false), "{file}");
        let got: Vec<&str> = cap["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(got, perms, "{file}");
    }
    assert_eq!(
        serde_json::from_str::<Value>(CAPABILITY).unwrap()["windows"],
        serde_json::json!(["settings"])
    );
    // The configuration enables exactly these capabilities.
    assert_eq!(
        conf()["app"]["security"]["capabilities"],
        serde_json::json!([
            "settings-window",
            "intro-window",
            "status-window",
            "setup-window",
            "clients-window",
            "updates-window"
        ])
    );
    for label in [
        crate::SETTINGS_LABEL,
        crate::INTRO_LABEL,
        crate::STATUS_LABEL,
        crate::SETUP_LABEL,
        crate::CLIENTS_LABEL,
        crate::UPDATES_LABEL,
    ] {
        assert_ne!(crate::console::CONSOLE_LABEL, label);
    }
}

#[test]
fn commands_are_declared_and_registered_once() {
    claims::partial(&["SR-2-5"]);
    let commands: Vec<String> = CAPABILITIES
        .iter()
        .flat_map(|c| c.3.iter())
        .map(|p| p.trim_start_matches("allow-").replace('-', "_"))
        .collect();
    // build.rs's application manifest makes every command need a permission.
    let build: String = BUILD.chars().filter(|c| !c.is_whitespace()).collect();
    let manifest = format!(
        ".commands(&[{},])",
        commands
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(build.contains(&manifest), "build.rs must list exactly {commands:?}");
    let compact: String = LIB.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains(&format!("tauri::generate_handler![{}]", commands.join(","))));
    // Each command refuses any window but its own, whatever the ACL says.
    assert_eq!(LIB.matches("only_settings_window(&webview)").count(), 2);
    assert_eq!(LIB.matches("only_window(&webview, INTRO_LABEL)").count(), 6);
    assert_eq!(LIB.matches("only_window(&webview, STATUS_LABEL)").count(), 4);
    assert_eq!(LIB.matches("only_window(&webview, SETUP_LABEL)").count(), 5);
    assert_eq!(LIB.matches("only_window(&webview, CLIENTS_LABEL)").count(), 4);
    assert_eq!(LIB.matches("only_window(&webview, UPDATES_LABEL)").count(), 5);
}

#[test]
fn bundled_pages_are_self_only() {
    claims::partial(&["SR-2-6"]);
    let c = conf();
    let csp = c["app"]["security"]["csp"].as_str().unwrap();
    let directives: Vec<&str> = csp.split(';').map(str::trim).collect();
    assert!(directives.contains(&"default-src 'self'"));
    assert!(directives.contains(&"script-src 'self'"));
    assert!(directives.contains(&"object-src 'none'"));
    assert!(directives.contains(&"frame-src 'none'"));
    for d in &directives {
        assert!(!d.contains("http:") || d.starts_with("connect-src"), "{d}");
        assert!(!d.contains("https:"), "{d}");
        assert!(
            !d.contains("'unsafe-inline'") && !d.contains("'unsafe-eval'") && !d.contains('*'),
            "{d}"
        );
    }
    assert_eq!(c["app"]["withGlobalTauri"], Value::Bool(false));
    assert_eq!(c["app"]["windows"], serde_json::json!([]));
    assert!(
        c["build"].get("devUrl").is_none(),
        "a dev URL would load remote content"
    );
    // The bundled pages reference only packaged files.
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../src");
    for f in [
        "settings.html",
        "error.html",
        "intro.html",
        "status.html",
        "setup.html",
        "clients.html",
        "updates.html",
    ] {
        let page = std::fs::read_to_string(dist.join(f)).unwrap();
        assert!(
            !page.contains("http://") && !page.contains("https://") && !page.contains("//cdn"),
            "{f} references a remote URL"
        );
    }
}

#[test]
fn no_updater_or_shell_plugin() {
    claims::partial(&["FR-20.13", "SR-2-5"]);
    for dep in [
        "tauri-plugin-updater",
        "tauri-plugin-shell",
        "tauri-plugin-process",
        "tauri-plugin-http",
        "tauri-plugin-fs",
    ] {
        assert!(!CARGO.contains(dep), "{dep} must not be a dependency");
    }
    let c = conf();
    assert!(c["plugins"].get("updater").is_none());
    assert!(c["bundle"].get("createUpdaterArtifacts").is_none());
    // Child processes are fixed argument vectors through std::process.
    assert!(!LIB.contains("Command::new"), "lib.rs spawns processes; use service.rs");
}

/// FR-20.28: the bundler registers the scheme `smcp` and no other; the
/// deep-link plugin itself is not used, so no window can register more.
#[test]
fn only_the_smcp_scheme_is_registered() {
    claims::partial(&["FR-20.28"]);
    let c = conf();
    assert_eq!(
        c["plugins"]["deep-link"],
        serde_json::json!({"desktop": {"schemes": ["smcp"]}})
    );
    assert_eq!(c["plugins"].as_object().unwrap().len(), 1);
    assert!(!CARGO.contains("tauri-plugin-deep-link"));
    // Links reach only deeplink::parse, then the console window.
    let compact: String = LIB.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("urls.iter().find_map(|u|deeplink::parse(u.as_str()))"));
    assert!(compact.contains("deeplink::from_args(std::env::args())"));
}

/// FR-20.20: the Windows installer embeds the WebView2 bootstrapper, which
/// the bundler's package runs only when no WebView2 runtime is installed,
/// so a host that has the runtime gets no download; the package refuses
/// a downgrade (SR-7-2: an older release is never installed over a newer
/// one); and the `smcp` scheme is registered by the package (the same
/// `plugins.deep-link` list, FR-20.28).
#[test]
fn the_windows_installer_embeds_the_webview2_bootstrapper() {
    claims::partial(&["FR-20.20", "FR-20.1"]);
    let c = conf();
    let w = &c["bundle"]["windows"];
    assert_eq!(
        w["webviewInstallMode"],
        serde_json::json!({"type": "embedBootstrapper", "silent": true})
    );
    assert_eq!(w["allowDowngrades"], serde_json::json!(false));
    assert_eq!(w["wix"]["language"], serde_json::json!("en-US"));
    // MSI only (WiX): no NSIS settings, no signing command.
    assert!(w.get("nsis").is_none() && w.get("signCommand").is_none());
}

#[test]
fn single_instance_is_the_first_plugin() {
    claims::partial(&["FR-20.14"]);
    assert!(CARGO.contains("tauri-plugin-single-instance"));
    let first_plugin = LIB.find(".plugin(").unwrap();
    assert_eq!(
        LIB[first_plugin..].find("tauri_plugin_single_instance::init"),
        Some(".plugin(".len())
    );
    // A second start opens or focuses the console window of the first.
    let compact: String = LIB.chars().filter(|c| !c.is_whitespace()).collect();
    let at = compact
        .find("tauri_plugin_single_instance::init(|app,argv,_cwd|")
        .unwrap();
    let body = &compact[at..at + 900];
    assert!(body.contains("deeplink::on_second_start(&argv)"));
    assert!(body.contains("open_console(app,page)"));
}

/// The version the application reports (`smcp-desktop --version`, and the
/// one the update check compares) is the configuration's `version`, which
/// the release build replaces with the tag's (build.sh passes it with
/// `--config`; scripts/desktop-smoke.sh checks the built installers).
#[test]
fn reported_version_is_the_configuration_version() {
    claims::partial(&["FR-20.11"]);
    let want = conf()["version"].as_str().unwrap().to_string();
    assert_eq!(crate::app_version(), want);
    let build = include_str!("../../../packaging/installers/desktop/build.sh");
    assert!(
        build.contains("{version: $v,") && build.contains("--config \"$work/tauri.json\""),
        "build.sh no longer sets the application's version"
    );
}

/// FR-20.28 on Linux: the desktop entry of the `.deb` and `.rpm` registers
/// the `smcp` scheme of the configuration and passes the link as the
/// argument the application reads (`deeplink::from_args`). Tauri's own
/// template does this from the configuration; the custom template must
/// too (the `v1.3.0-beta.2` packages lacked it).
#[test]
fn linux_desktop_entry_registers_the_link_scheme() {
    claims::partial(&["FR-20.28"]);
    let entry = include_str!("../../../packaging/installers/desktop/smcp-desktop.desktop");
    let schemes = conf()["plugins"]["deep-link"]["desktop"]["schemes"].clone();
    assert_eq!(schemes, serde_json::json!(["smcp"]));
    assert!(entry.lines().any(|l| l == "MimeType=x-scheme-handler/smcp;"), "{entry}");
    assert!(entry.lines().any(|l| l == "Exec={{exec}} %u"), "{entry}");
}

/// Inside `with_webview` the console window loads its first page through
/// WebKit, on macOS as on Linux, not through a Tauri navigation, which
/// waits on the main thread the closure holds (#177).
#[test]
fn console_first_page_loads_through_webkit() {
    claims::partial(&["FR-20.6"]);
    let at = LIB
        .find("let _ = w.with_webview(")
        .expect("with_webview in open_console");
    let end = LIB[at..].find("\n    });").expect("end of with_webview") + at;
    let body = &LIB[at..end];
    assert!(!body.contains(".navigate("), "a Tauri navigation inside with_webview");
    assert!(body.contains("tlshook_macos::load("));
    assert!(body.contains("WebViewExt::load_uri("));
}
