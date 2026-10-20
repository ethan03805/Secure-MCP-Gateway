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
        let src = std::fs::read_to_string(&path).unwrap();
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
const CAPABILITIES: [(&str, &str, &str, &[&str]); 5] = [
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
            "clients-window"
        ])
    );
    for label in [
        crate::SETTINGS_LABEL,
        crate::INTRO_LABEL,
        crate::STATUS_LABEL,
        crate::SETUP_LABEL,
        crate::CLIENTS_LABEL,
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
