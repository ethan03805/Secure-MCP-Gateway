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
            assert!(!code.contains(needle), "{name} mentions {needle}");
        }
        checked += 1;
    }
    assert!(checked >= 8, "only {checked} source files checked");
}

#[test]
fn one_capability_for_the_settings_window_only() {
    claims::partial(&["SR-2-5"]);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(files, ["settings.json"], "unexpected capability files");
    let cap: Value = serde_json::from_str(CAPABILITY).unwrap();
    assert_eq!(cap["windows"], serde_json::json!(["settings"]));
    assert!(cap.get("webviews").is_none());
    assert!(cap.get("remote").is_none(), "a capability lists a remote URL");
    assert_ne!(cap["local"], Value::Bool(false));
    let perms: Vec<&str> = cap["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(perms, ["allow-get-settings", "allow-save-settings"]);
    // The configuration enables exactly this capability.
    assert_eq!(
        conf()["app"]["security"]["capabilities"],
        serde_json::json!(["settings-window"])
    );
    assert_ne!(crate::console::CONSOLE_LABEL, crate::SETTINGS_LABEL);
}

#[test]
fn commands_are_declared_and_registered_once() {
    claims::partial(&["SR-2-5"]);
    // build.rs's application manifest makes every command need a permission.
    assert!(BUILD.contains(r#".commands(&["get_settings", "save_settings"])"#));
    let compact: String = LIB.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("tauri::generate_handler![get_settings,save_settings]"));
    // Each command refuses any window but Settings, whatever the ACL says.
    assert_eq!(LIB.matches("only_settings_window(&webview)").count(), 2);
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
    for f in ["settings.html", "error.html"] {
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
        .find("tauri_plugin_single_instance::init(|app,_argv,_cwd|")
        .unwrap();
    assert!(compact[at..at + 100].contains("open_console(app,Page::Home)"));
}
