//! Start at login (SRS FR-20.14). Off after installation; the Settings
//! switch turns it on or off. The application registers itself the way each
//! platform expects for a per-user login item, with no elevation:
//!
//! - macOS: the launch agent `~/Library/LaunchAgents/com.smcp.desktop.plist`
//!   with `RunAtLoad`, loaded by launchd at the next login;
//! - Linux: the XDG autostart entry
//!   `$XDG_CONFIG_HOME/autostart/smcp-desktop.desktop` (an AppImage registers
//!   its `$APPIMAGE` file, which stays where the user put it);
//! - Windows: the value `Secure MCP Gateway` under
//!   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, written with
//!   `reg.exe`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::service::{Host, Runner};

pub const LABEL: &str = "com.smcp.desktop";
pub const DESKTOP_FILE: &str = "smcp-desktop.desktop";
pub const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
pub const RUN_VALUE: &str = "Secure MCP Gateway";
const REG: &str = r"C:\Windows\System32\reg.exe";

/// The file that registers the login item (macOS, Linux).
pub fn entry_path(h: &Host) -> Option<PathBuf> {
    match h.os {
        "macos" => Some(h.home.join("Library/LaunchAgents").join(format!("{LABEL}.plist"))),
        "linux" => Some(
            h.xdg_config_home
                .clone()
                .unwrap_or_else(|| h.home.join(".config"))
                .join("autostart")
                .join(DESKTOP_FILE),
        ),
        _ => None,
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The launch agent that starts the application at login (macOS).
pub fn plist(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#,
        xml_escape(&exe.display().to_string())
    )
}

/// Quotes a path for the Exec key of a desktop entry (Desktop Entry
/// Specification, "The Exec key").
fn exec_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    // `%` is a field code; a literal one is written `%%`.
    out.replace('%', "%%")
}

/// The XDG autostart entry (Linux).
pub fn desktop_entry(exe: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=Secure MCP Gateway\nComment=Tray for the Secure MCP Gateway\nExec={}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
        exec_quote(&exe.display().to_string())
    )
}

/// The `reg.exe` argument vector that adds or removes the Run value
/// (Windows).
pub fn reg_argv(exe: &Path, enable: bool) -> Vec<String> {
    let mut v = vec![REG.to_string()];
    if enable {
        v.extend([
            "add".into(),
            RUN_KEY.into(),
            "/v".into(),
            RUN_VALUE.into(),
            "/t".into(),
            "REG_SZ".into(),
            "/d".into(),
            format!("\"{}\"", exe.display()),
            "/f".into(),
        ]);
    } else {
        v.extend([
            "delete".into(),
            RUN_KEY.into(),
            "/v".into(),
            RUN_VALUE.into(),
            "/f".into(),
        ]);
    }
    v
}

/// The program to start at login: the AppImage file when the application
/// runs from one, else this executable.
pub fn program(exe: PathBuf, appimage: Option<PathBuf>) -> PathBuf {
    appimage.filter(|p| p.is_absolute()).unwrap_or(exe)
}

/// Turns start at login on or off.
pub fn apply(h: &Host, exe: &Path, enable: bool, runner: &dyn Runner) -> Result<(), String> {
    if h.os == "windows" {
        let argv = reg_argv(exe, enable);
        let r = runner.run(&argv, Duration::from_secs(10));
        // Deleting a value that is not there is not an error here.
        return if r.code == Some(0) || (!enable && r.code == Some(1)) {
            Ok(())
        } else {
            Err(format!(
                "reg.exe: {}{}",
                r.stderr.trim(),
                r.spawn_error.unwrap_or_default()
            ))
        };
    }
    let Some(path) = entry_path(h) else {
        return Err(format!("start at login is not available on {}", h.os));
    };
    if !enable {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        };
    }
    let body = if h.os == "macos" {
        plist(exe)
    } else {
        desktop_entry(exe)
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Whether the login item is registered (macOS, Linux).
pub fn registered(h: &Host) -> bool {
    entry_path(h).is_some_and(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use crate::service::RunResult;
    use std::sync::Mutex;

    struct Rec(Mutex<Vec<Vec<String>>>, i32);
    impl Runner for Rec {
        fn run(&self, argv: &[String], _t: Duration) -> RunResult {
            self.0.lock().unwrap().push(argv.to_vec());
            RunResult {
                code: Some(self.1),
                ..Default::default()
            }
        }
    }

    fn host(os: &'static str, name: &str) -> (PathBuf, Host) {
        let root = std::env::temp_dir().join(format!("smcp-desktop-autostart-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        (
            root.clone(),
            Host {
                os,
                home: root.join("home"),
                xdg_config_home: None,
                etc_systemd: root.join("etc/systemd/system"),
                uid: 501,
                win: Default::default(),
            },
        )
    }

    #[test]
    fn off_until_turned_on_and_off_again() {
        claims::partial(&["FR-20.14"]);
        assert!(!crate::settings::Settings::default().start_at_login);
        for os in ["macos", "linux"] {
            let (root, h) = host(os, os);
            let r = Rec(Mutex::new(vec![]), 0);
            assert!(!registered(&h));
            apply(
                &h,
                Path::new("/Applications/Secure MCP Gateway.app/Contents/MacOS/smcp-desktop"),
                true,
                &r,
            )
            .unwrap();
            assert!(registered(&h));
            let body = std::fs::read_to_string(entry_path(&h).unwrap()).unwrap();
            assert!(body.contains("smcp-desktop"), "{body}");
            apply(&h, Path::new("/x"), false, &r).unwrap();
            assert!(!registered(&h));
            // Turning it off twice is fine.
            apply(&h, Path::new("/x"), false, &r).unwrap();
            assert!(r.0.lock().unwrap().is_empty(), "no command runs on {os}");
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn entries_name_this_program_only() {
        claims::partial(&["FR-20.14"]);
        let (_, mac) = host("macos", "paths");
        assert!(entry_path(&mac)
            .unwrap()
            .ends_with("Library/LaunchAgents/com.smcp.desktop.plist"));
        let p = plist(Path::new("/Applications/A & B.app/Contents/MacOS/smcp-desktop"));
        assert!(p.contains("<string>/Applications/A &amp; B.app/Contents/MacOS/smcp-desktop</string>"));
        assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(!p.contains("com.smcp.gateway"), "the Gateway's own agent is separate");
        let d = desktop_entry(Path::new("/home/u/Apps/Secure \"MCP\" $1 50%.AppImage"));
        assert!(
            d.contains(r#"Exec="/home/u/Apps/Secure \"MCP\" \$1 50%%.AppImage""#),
            "{d}"
        );
        assert_eq!(
            program(
                PathBuf::from("/tmp/.mount_x/usr/bin/smcp-desktop"),
                Some(PathBuf::from("/home/u/smcp.AppImage"))
            ),
            PathBuf::from("/home/u/smcp.AppImage")
        );
        assert_eq!(
            program(PathBuf::from("/usr/bin/smcp-desktop"), None),
            PathBuf::from("/usr/bin/smcp-desktop")
        );
    }

    #[test]
    fn windows_uses_the_run_key_of_the_user() {
        claims::partial(&["FR-20.14", "SR-2-7"]);
        let exe = Path::new(r"C:\Program Files\Secure MCP Gateway\smcp-desktop.exe");
        let on = reg_argv(exe, true);
        assert_eq!(on[0], r"C:\Windows\System32\reg.exe");
        assert_eq!(on[2], r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run");
        assert!(on.contains(&format!("\"{}\"", exe.display())));
        let off = reg_argv(exe, false);
        assert_eq!(off[1], "delete");
        let (_, h) = host("windows", "win");
        let r = Rec(Mutex::new(vec![]), 0);
        apply(&h, exe, true, &r).unwrap();
        assert_eq!(r.0.lock().unwrap()[0], on);
        // Removing a value that does not exist (reg.exe exits 1) is fine.
        apply(&h, exe, false, &Rec(Mutex::new(vec![]), 1)).unwrap();
        assert!(apply(&h, exe, true, &Rec(Mutex::new(vec![]), 1)).is_err());
    }
}
