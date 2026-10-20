//! The Gateway commands the Desktop Application runs (SRS FR-20.17,
//! FR-20.19): `smcpd`, `smcpctl`, `smcp-session`, `smcp-stdio`,
//! `smcp-connect` and `smcp-refserver`.
//!
//! Each installer puts them next to the application's own executable:
//! `Contents/MacOS` of the application bundle in the `.dmg` and the `.pkg`,
//! `usr/bin` inside the AppImage, and `/usr/bin` for the `smcp-desktop`
//! `.deb` and `.rpm`, whose dependency `smcp` installs them there. The
//! application looks there first and then in the fixed directories the
//! command-line packages use, never in a directory taken from `PATH`, so
//! a writable directory early on the user's `PATH` cannot substitute a
//! command.
//!
//! `smcp-desktop --commands` prints where each command was found and the
//! version it reports, and exits non-zero when one is missing; the
//! installer smoke tests (`scripts/desktop-smoke.sh`) run it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The commands every installer of the application provides.
pub const COMMANDS: [&str; 6] = [
    "smcpd",
    "smcpctl",
    "smcp-session",
    "smcp-stdio",
    "smcp-connect",
    "smcp-refserver",
];

/// The fixed directories searched after the application's own directory.
#[cfg(target_os = "macos")]
const FIXED_DIRS: &[&str] = &["/usr/local/bin"];
#[cfg(all(unix, not(target_os = "macos")))]
const FIXED_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin"];
#[cfg(not(unix))]
const FIXED_DIRS: &[&str] = &[];

fn file_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

/// The directories searched for a command, in order: the directory of
/// `exe` (the application's executable), then the fixed directories.
pub fn search_dirs(exe: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = exe.parent() {
        dirs.push(d.to_path_buf());
    }
    for d in FIXED_DIRS {
        let p = PathBuf::from(d);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    dirs
}

/// Finds a Gateway command in `dirs`: the first regular file of that name.
pub fn find_in(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    let f = file_name(name);
    dirs.iter().map(|d| d.join(&f)).find(|p| p.is_file())
}

/// Finds a Gateway command for the running application.
pub fn find(name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    find_in(name, &search_dirs(&exe))
}

/// The version a command reports: `smcpctl version --short` prints the
/// bare version, the others `<name> <version>` for `--version`.
pub fn version_of(name: &str, path: &Path) -> Option<String> {
    let args: &[&str] = if name == "smcpctl" {
        &["version", "--short"]
    } else {
        &["--version"]
    };
    let out = Command::new(path).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let text = if text.is_empty() {
        String::from_utf8_lossy(&out.stderr).trim().to_string()
    } else {
        text
    };
    let v = text.strip_prefix(&format!("{name} ")).unwrap_or(&text);
    (!v.is_empty()).then(|| v.to_string())
}

/// One line per command for `--commands`, and whether all were found and
/// answered with a version.
pub fn report(dirs: &[PathBuf]) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut ok = true;
    for name in COMMANDS {
        match find_in(name, dirs) {
            Some(p) => match version_of(name, &p) {
                Some(v) => lines.push(format!("{name}\t{}\t{v}", p.display())),
                None => {
                    ok = false;
                    lines.push(format!("{name}\t{}\tno version", p.display()));
                }
            },
            None => {
                ok = false;
                lines.push(format!("{name}\tnot found"));
            }
        }
    }
    (lines, ok)
}

/// `smcp-desktop --commands`: prints the report and returns the exit code.
pub fn print_report() -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => std::fs::canonicalize(&e).unwrap_or(e),
        Err(e) => {
            eprintln!("smcp-desktop: cannot locate its own executable: {e}");
            return 1;
        }
    };
    let (lines, ok) = report(&search_dirs(&exe));
    for l in lines {
        println!("{l}");
    }
    if ok {
        0
    } else {
        1
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("smcp-commands-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn own_directory_first_then_fixed_and_never_path() {
        crate::claims::partial(&["FR-20.17", "FR-20.19"]);
        let dirs = search_dirs(Path::new("/Applications/X.app/Contents/MacOS/smcp-desktop"));
        assert_eq!(dirs[0], PathBuf::from("/Applications/X.app/Contents/MacOS"));
        // Then exactly the fixed directories: nothing from PATH.
        let rest: Vec<PathBuf> = FIXED_DIRS.iter().map(PathBuf::from).collect();
        assert_eq!(dirs[1..], rest[..]);
        // The .deb and .rpm: the application is in /usr/bin itself.
        let dirs = search_dirs(Path::new("/usr/bin/smcp-desktop"));
        assert_eq!(dirs[0], PathBuf::from("/usr/bin"));
        assert_eq!(dirs.iter().filter(|d| *d == Path::new("/usr/bin")).count(), 1);
    }

    #[test]
    fn bundled_commands_are_found_with_their_versions() {
        crate::claims::partial(&["FR-20.17", "FR-20.19"]);
        let own = tempdir("own");
        let fixed = tempdir("fixed");
        for name in COMMANDS {
            if name == "smcpctl" {
                script(&own, name, "[ \"$1 $2\" = 'version --short' ] && echo 1.3.0");
            } else {
                script(&own, name, &format!("echo '{name} 1.3.0'"));
            }
            // A decoy in the later directory is never chosen.
            script(&fixed, name, "echo decoy");
        }
        let dirs = vec![own.clone(), fixed.clone()];
        let (lines, ok) = report(&dirs);
        assert!(ok, "{lines:?}");
        for (name, line) in COMMANDS.iter().zip(&lines) {
            assert_eq!(line, &format!("{name}\t{}\t1.3.0", own.join(name).display()));
        }
        // A missing command fails the report and is named.
        std::fs::remove_file(own.join("smcp-connect")).unwrap();
        std::fs::remove_file(fixed.join("smcp-connect")).unwrap();
        let (lines, ok) = report(&dirs);
        assert!(!ok);
        assert!(lines.contains(&"smcp-connect\tnot found".to_string()));
        let _ = std::fs::remove_dir_all(own);
        let _ = std::fs::remove_dir_all(fixed);
    }
}
