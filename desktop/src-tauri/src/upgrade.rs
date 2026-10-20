//! Gateway upgrade from the desktop (SRS FR-20.12, SR-7-2, I-42).
//!
//! The application upgrades the Gateway only by running `smcpctl upgrade`
//! for a release it has downloaded and verified itself (`verify`), so the
//! release is checked twice, once here and once by `smcpctl` with its own
//! embedded key. The installation to upgrade is the one the service
//! manager runs: the `smcpd` path and the `--config` argument come from the
//! Standalone service definition (`smcpctl install` writes them), and
//! `smcpctl` from the same directory is run with a fixed argument vector.
//! The backup passphrase that `smcpctl upgrade` needs is written to its
//! standard input and never to an argument or a file. The application
//! reads neither the configuration nor anything else of the installation.
//!
//! An Enforced installation (system unit) is not upgraded from here: it
//! would need elevation, which SR-2-7 does not allow for this; the window
//! shows the terminal command instead. A binary directory that a platform
//! package owns is upgraded with the package (FR-20.13), not `smcpctl`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use semver::Version;

use crate::service::Manager;

/// CP-47 allows 60 s for health and 120 s for migrations; the backup and
/// the service restarts come on top. The upgrade is killed after this.
pub const UPGRADE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
/// `cmd/smcpctl/platformpkg.go`: a package writes this marker beside the
/// binaries (or in `../lib/smcp/`).
const PACKAGE_MARKER: &str = "package-format";
/// Output kept for the details area.
const MAX_OUTPUT: usize = 256 * 1024;

/// The installation the Standalone service runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    /// The directory of `smcpd` (and of `smcpctl`, which upgrade replaces).
    pub bin_dir: PathBuf,
    /// The `--config` argument of the service.
    pub config: PathBuf,
}

impl Installation {
    pub fn smcpctl(&self) -> PathBuf {
        self.bin_dir.join(if cfg!(windows) { "smcpctl.exe" } else { "smcpctl" })
    }
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&#34;", "\"")
        .replace("&amp;", "&")
}

/// The program arguments of the launchd user agent `smcpctl install`
/// writes.
pub fn plist_program_arguments(plist: &str) -> Vec<String> {
    let Some(start) = plist.find("<key>ProgramArguments</key>") else {
        return Vec::new();
    };
    let rest = &plist[start..];
    let Some(end) = rest.find("</array>") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut s = &rest[..end];
    while let Some(i) = s.find("<string>") {
        let after = &s[i + "<string>".len()..];
        let Some(j) = after.find("</string>") else { break };
        out.push(xml_unescape(&after[..j]));
        s = &after[j..];
    }
    out
}

/// The words of the `ExecStart=` line of the systemd user unit
/// `smcpctl install` writes (words quoted as `systemdQuote` quotes them).
pub fn systemd_exec_start(unit: &str) -> Vec<String> {
    let Some(line) = unit.lines().find_map(|l| l.trim().strip_prefix("ExecStart=")) else {
        return Vec::new();
    };
    let mut words = Vec::new();
    let mut chars = line.trim().chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut w = String::new();
        if c == '"' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' => {
                        if let Some(n) = chars.next() {
                            w.push(n);
                        }
                    }
                    '"' => break,
                    '%' if chars.peek() == Some(&'%') => {
                        chars.next();
                        w.push('%');
                    }
                    c => w.push(c),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                w.push(c);
                chars.next();
            }
        }
        words.push(w);
    }
    words
}

/// The installation from the service's program arguments:
/// `<dir>/smcpd --config <path>` with absolute paths.
pub fn installation_from_args(args: &[String]) -> Option<Installation> {
    let smcpd = Path::new(args.first()?);
    let name = smcpd.file_name()?.to_str()?;
    if !smcpd.is_absolute() || !(name == "smcpd" || name == "smcpd.exe") {
        return None;
    }
    let i = args.iter().position(|a| a == "--config")?;
    let config = PathBuf::from(args.get(i + 1)?);
    if !config.is_absolute() {
        return None;
    }
    Some(Installation {
        bin_dir: smcpd.parent()?.to_path_buf(),
        config,
    })
}

/// Why the Gateway cannot be upgraded from the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotHere {
    /// No Gateway service is installed.
    NotInstalled,
    /// The Enforced system service; upgrade in a terminal as root.
    Enforced,
    /// A platform package owns the binaries; update the package.
    Packaged(String),
    /// The service definition could not be read.
    Unreadable(String),
    /// A Windows installation: there is no Windows release archive for
    /// this window; upgrade with `smcpctl upgrade` or the `.msi`.
    Windows,
}

/// Finds the Standalone installation the service manager runs.
pub fn find_installation(
    m: Option<&Manager>,
    unit_file: impl Fn(&Manager) -> Option<PathBuf>,
) -> Result<Installation, NotHere> {
    let m = m.ok_or(NotHere::NotInstalled)?;
    if *m == Manager::SystemdSystem {
        return Err(NotHere::Enforced);
    }
    if matches!(m, Manager::WindowsUser { .. } | Manager::WindowsMachine { .. }) {
        return Err(NotHere::Windows);
    }
    let path = unit_file(m).ok_or(NotHere::NotInstalled)?;
    let text = std::fs::read_to_string(&path).map_err(|e| NotHere::Unreadable(format!("{}: {e}", path.display())))?;
    let args = match m {
        Manager::Launchd { .. } => plist_program_arguments(&text),
        _ => systemd_exec_start(&text),
    };
    let inst = installation_from_args(&args)
        .ok_or_else(|| NotHere::Unreadable(format!("{} does not name smcpd and --config", path.display())))?;
    if let Some(f) = package_format(&inst.bin_dir) {
        return Err(NotHere::Packaged(f));
    }
    Ok(inst)
}

/// The service definition `smcpctl install` wrote for a Standalone
/// service: the launchd plist, or the systemd user unit.
pub fn unit_file(h: &crate::service::Host, m: &Manager) -> Option<PathBuf> {
    match m {
        Manager::Launchd { plist, .. } => Some(plist.clone()),
        Manager::SystemdUser => Some(
            h.xdg_config_home
                .clone()
                .unwrap_or_else(|| h.home.join(".config"))
                .join("systemd/user")
                .join(crate::service::SYSTEMD_UNIT),
        ),
        Manager::SystemdSystem | Manager::WindowsUser { .. } | Manager::WindowsMachine { .. } => None,
    }
}

/// The platform package that owns `bin_dir`, as `smcpctl` decides it.
pub fn package_format(bin_dir: &Path) -> Option<String> {
    let d = std::fs::canonicalize(bin_dir).unwrap_or_else(|_| bin_dir.to_path_buf());
    for p in [d.join(PACKAGE_MARKER), d.join("../lib/smcp").join(PACKAGE_MARKER)] {
        if let Ok(s) = std::fs::read_to_string(p) {
            let f = s.trim();
            if ["deb", "rpm", "pkg"].contains(&f) {
                return Some(f.to_string());
            }
        }
    }
    None
}

/// The release archive `smcpctl upgrade` installs on this platform.
pub fn archive_name(v: &Version, os: &str, arch: &str) -> Option<String> {
    let goos = match os {
        "macos" => "darwin",
        "linux" => "linux",
        _ => return None,
    };
    let goarch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    Some(format!("smcp_{v}_{goos}_{goarch}.tar.gz"))
}

/// `smcpctl version --short`.
pub fn version_argv(smcpctl: &Path) -> Vec<String> {
    vec![smcpctl.display().to_string(), "version".into(), "--short".into()]
}

/// `smcpctl upgrade` for the verified release in `release_dir`, with the
/// backup passphrase on standard input.
pub fn upgrade_argv(inst: &Installation, release_dir: &Path) -> Vec<String> {
    vec![
        inst.smcpctl().display().to_string(),
        "upgrade".into(),
        "--config".into(),
        inst.config.display().to_string(),
        "--release".into(),
        release_dir.display().to_string(),
        "--passphrase-file".into(),
        "-".into(),
    ]
}

/// The result of a child process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ran {
    pub code: Option<i32>,
    /// Standard output and standard error, interleaved, bounded.
    pub output: String,
    pub timed_out: bool,
    pub spawn_error: Option<String>,
}

impl Ran {
    /// A one-line account for an error's details.
    pub fn summary(&self) -> String {
        if let Some(e) = &self.spawn_error {
            return e.clone();
        }
        if self.timed_out {
            return format!("did not finish in time\n{}", self.output);
        }
        format!("exit status {:?}\n{}", self.code, self.output)
    }
}

/// Runs a fixed argument vector with `std::process`: no shell, an absolute
/// program, `stdin` written then closed (or none), each output line passed
/// to `on_line` as it arrives, and a kill at `timeout`.
pub fn run_fixed(argv: &[String], stdin: Option<&str>, timeout: Duration, on_line: &mut dyn FnMut(&str)) -> Ran {
    let Some((prog, args)) = argv.split_first() else {
        return Ran {
            spawn_error: Some("empty command".into()),
            ..Default::default()
        };
    };
    if !Path::new(prog).is_absolute() {
        return Ran {
            spawn_error: Some(format!("{prog} is not an absolute path")),
            ..Default::default()
        };
    }
    let mut child = match crate::service::no_console(&mut Command::new(prog))
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Ran {
                spawn_error: Some(format!("{prog}: {e}")),
                ..Default::default()
            }
        }
    };
    if let (Some(s), Some(mut w)) = (stdin, child.stdin.take()) {
        let _ = w.write_all(s.as_bytes());
        let _ = w.write_all(b"\n");
        // Dropping w closes standard input.
    }
    let (tx, rx) = mpsc::channel::<String>();
    let readers: Vec<_> = [
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|p| {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(p).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        })
    })
    .collect();
    drop(tx);
    let start = Instant::now();
    let mut output = String::new();
    let mut take = |line: String, output: &mut String| {
        on_line(&line);
        if output.len() < MAX_OUTPUT {
            output.push_str(&line);
            output.push('\n');
        }
    };
    let (code, timed_out) = loop {
        while let Ok(line) = rx.try_recv() {
            take(line, &mut output);
        }
        match child.try_wait() {
            Ok(Some(st)) => break (st.code(), false),
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break (None, true);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                return Ran {
                    spawn_error: Some(e.to_string()),
                    output,
                    ..Default::default()
                }
            }
        }
    };
    for r in readers {
        let _ = r.join();
    }
    while let Ok(line) = rx.try_recv() {
        take(line, &mut output);
    }
    Ran {
        code,
        output,
        timed_out,
        spawn_error: None,
    }
}

/// The installed Gateway's version, from `smcpctl version --short`.
pub fn installed_version(smcpctl: &Path) -> Option<Version> {
    let r = run_fixed(&version_argv(smcpctl), None, VERSION_TIMEOUT, &mut |_| {});
    if r.code != Some(0) {
        return None;
    }
    Version::parse(r.output.trim().trim_start_matches('v')).ok()
}

/// The outcome of `smcpctl upgrade`, as the window reports it (FR-20.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The new version runs.
    Upgraded { from: String, to: String },
    /// The upgrade failed and `smcpctl` rolled back: a failed upgrade with
    /// the version that runs afterwards (`UPGRADE_ROLLED_BACK`).
    RolledBack { running: String },
    /// Any other failure, with the version installed afterwards
    /// (`UPGRADE_FAILED`).
    Failed { running: String },
}

/// The `from` and `to` of `upgrade: upgrading from A to B`.
fn from_to(output: &str) -> Option<(String, String)> {
    output.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("upgrade: upgrading from ")?;
        let (a, b) = rest.split_once(" to ")?;
        Some((a.trim().to_string(), b.trim().to_string()))
    })
}

/// Classifies a finished `smcpctl upgrade` by its exit status and the
/// messages of `cmd/smcpctl/upgrade.go`. `before` is the version installed
/// before the upgrade, `after` the version `smcpctl version` reports
/// afterwards.
pub fn classify(r: &Ran, before: Option<&Version>, after: Option<&Version>) -> Outcome {
    let ft = from_to(&r.output);
    let show = |v: Option<&Version>| v.map(|v| v.to_string());
    if r.code == Some(0) && !r.timed_out {
        let (from, to) = ft.unwrap_or_default();
        return Outcome::Upgraded {
            from: if from.is_empty() {
                show(before).unwrap_or_else(|| "unknown".into())
            } else {
                from
            },
            to: show(after).unwrap_or(to),
        };
    }
    let unknown = || "unknown".to_string();
    if r.output.contains("upgrade rolled back:") && !r.output.contains("the rollback had errors") {
        // The previous binaries and state were restored and started.
        let running = ft
            .map(|(f, _)| f)
            .filter(|f| f != "unknown")
            .or_else(|| show(after))
            .or_else(|| show(before))
            .unwrap_or_else(unknown);
        return Outcome::RolledBack { running };
    }
    if r.output.contains("nothing changed") {
        return Outcome::Failed {
            running: show(before).or_else(|| show(after)).unwrap_or_else(unknown),
        };
    }
    Outcome::Failed {
        running: show(after).unwrap_or_else(unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    #[cfg_attr(not(unix), allow(dead_code))]
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "smcp-desktop-up-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The exact files `smcpctl install` writes (cmd/smcpctl/install.go),
    /// with a path that needs escaping.
    #[cfg(unix)]
    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.smcp.gateway</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Users/a b/.local/bin/smcpd</string>
		<string>--config</string>
		<string>/Users/a b/Library/Application Support/smcp-gateway/config/R&amp;D.toml</string>
	</array>
	<key>StandardOutPath</key>
	<string>/Users/a b/Library/Logs/smcp-gateway/launchd.log</string>
</dict>
</plist>
"#;
    #[cfg(unix)]
    const UNIT: &str = "[Service]\nType=simple\nExecStart=\"/home/a/.local/bin/smcpd\" --config \"/home/a/.config/smcp-gateway/100%% \\\"x\\\".toml\"\nRestart=on-failure\n";

    // The Gateway upgrade of this window is for launchd and systemd
    // installations; the paths in these tests are Unix paths.
    #[cfg(unix)]
    #[test]
    fn installation_comes_from_the_service_definition() {
        claims::partial(&["FR-20.12"]);
        let a = plist_program_arguments(PLIST);
        let i = installation_from_args(&a).unwrap();
        assert_eq!(i.bin_dir, PathBuf::from("/Users/a b/.local/bin"));
        assert_eq!(
            i.config,
            PathBuf::from("/Users/a b/Library/Application Support/smcp-gateway/config/R&D.toml")
        );
        let i = installation_from_args(&systemd_exec_start(UNIT)).unwrap();
        assert_eq!(i.bin_dir, PathBuf::from("/home/a/.local/bin"));
        assert_eq!(i.config, PathBuf::from("/home/a/.config/smcp-gateway/100% \"x\".toml"));
        // Not smcpd, relative paths, no --config: refused.
        for bad in [
            vec!["/bin/sh", "--config", "/c"],
            vec!["smcpd", "--config", "/c"],
            vec!["/b/smcpd", "--config", "c"],
            vec!["/b/smcpd"],
        ] {
            let v: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
            assert_eq!(installation_from_args(&v), None, "{bad:?}");
        }
    }

    #[test]
    fn windows_installations_are_not_upgraded_here() {
        claims::partial(&["FR-20.12"]);
        for m in [
            Manager::WindowsUser {
                smcpctl: "C:\\p\\smcpctl.exe".into(),
                config: "C:\\c\\smcp.toml".into(),
            },
            Manager::WindowsMachine {
                smcpctl: "C:\\p\\smcpctl.exe".into(),
                config: "C:\\c\\smcp.toml".into(),
            },
        ] {
            assert_eq!(find_installation(Some(&m), |_| None), Err(NotHere::Windows));
            let h = crate::service::Host {
                os: "windows",
                home: "C:\\Users\\a".into(),
                xdg_config_home: None,
                etc_systemd: "C:\\none".into(),
                uid: 0,
                win: Default::default(),
            };
            assert_eq!(unit_file(&h, &m), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn enforced_packaged_and_missing_installations_are_not_upgraded_here() {
        claims::partial(&["FR-20.12", "SR-2-7"]);
        assert_eq!(find_installation(None, |_| None), Err(NotHere::NotInstalled));
        assert_eq!(
            find_installation(Some(&Manager::SystemdSystem), |_| None),
            Err(NotHere::Enforced)
        );
        let d = tmp("pkg");
        let bin = d.join("usr/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(d.join("usr/lib/smcp")).unwrap();
        std::fs::write(d.join("usr/lib/smcp").join(PACKAGE_MARKER), "deb\n").unwrap();
        let unit = d.join("smcpd.service");
        std::fs::write(
            &unit,
            format!("ExecStart=\"{}/smcpd\" --config \"/c/x.toml\"\n", bin.display()),
        )
        .unwrap();
        assert_eq!(
            find_installation(Some(&Manager::SystemdUser), |_| Some(unit.clone())),
            Err(NotHere::Packaged("deb".into()))
        );
        std::fs::remove_file(d.join("usr/lib/smcp").join(PACKAGE_MARKER)).unwrap();
        let i = find_installation(Some(&Manager::SystemdUser), |_| Some(unit.clone())).unwrap();
        assert_eq!(i.smcpctl(), bin.join("smcpctl"));
        let h = crate::service::Host {
            os: "linux",
            home: "/home/a".into(),
            xdg_config_home: None,
            etc_systemd: "/etc/systemd/system".into(),
            uid: 1000,
            win: Default::default(),
        };
        assert_eq!(
            unit_file(&h, &Manager::SystemdUser),
            Some(PathBuf::from("/home/a/.config/systemd/user/smcpd.service"))
        );
        assert_eq!(unit_file(&h, &Manager::SystemdSystem), None);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn argv_is_fixed_and_carries_no_passphrase() {
        claims::partial(&["FR-20.12"]);
        let i = Installation {
            bin_dir: "/home/a/.local/bin".into(),
            config: "/home/a/.config/smcp-gateway/c.toml".into(),
        };
        assert_eq!(
            upgrade_argv(&i, Path::new("/tmp/rel")),
            [
                "/home/a/.local/bin/smcpctl",
                "upgrade",
                "--config",
                "/home/a/.config/smcp-gateway/c.toml",
                "--release",
                "/tmp/rel",
                "--passphrase-file",
                "-"
            ]
        );
        let v = Version::new(1, 4, 0);
        assert_eq!(
            archive_name(&v, "macos", "aarch64").unwrap(),
            "smcp_1.4.0_darwin_arm64.tar.gz"
        );
        assert_eq!(
            archive_name(&v, "linux", "x86_64").unwrap(),
            "smcp_1.4.0_linux_amd64.tar.gz"
        );
        assert_eq!(archive_name(&v, "windows", "x86_64"), None);
    }

    /// The messages below are those of cmd/smcpctl/upgrade.go.
    #[test]
    fn outcomes_report_a_rollback_as_a_failure_with_the_running_version() {
        claims::partial(&["FR-20.12"]);
        let v = |s: &str| Version::parse(s).unwrap();
        let ran = |code: i32, out: &str| Ran {
            code: Some(code),
            output: out.into(),
            ..Default::default()
        };
        let ok = ran(0, "upgrade: release verified: signature of smcp_1.4.0_checksums.txt and checksum of smcp_1.4.0_darwin_arm64.tar.gz\nupgrade: upgrading from 1.3.0 to 1.4.0\nupgrade: upgrade complete; the previous binaries are kept as <name>.prev in /b\n");
        assert_eq!(
            classify(&ok, Some(&v("1.3.0")), Some(&v("1.4.0"))),
            Outcome::Upgraded {
                from: "1.3.0".into(),
                to: "1.4.0".into()
            }
        );
        let rolled = ran(1, "upgrade: upgrading from 1.3.0 to 1.4.0\nupgrade: rolling back: migration failed: exit status 1\nsmcpctl: upgrade rolled back: migration failed: exit status 1; the previous version is running\n");
        assert_eq!(
            classify(&rolled, Some(&v("1.3.0")), Some(&v("1.3.0"))),
            Outcome::RolledBack {
                running: "1.3.0".into()
            }
        );
        let broken = ran(1, "upgrade: upgrading from 1.3.0 to 1.4.0\nsmcpctl: upgrade failed (start failed) and the rollback had errors: x\n");
        assert_eq!(
            classify(&broken, Some(&v("1.3.0")), None),
            Outcome::Failed {
                running: "unknown".into()
            }
        );
        let refused = ran(1, "smcpctl: release verification failed, nothing changed: the minisign signature of smcp_1.4.0_checksums.txt does not verify with the release key\n");
        assert_eq!(
            classify(&refused, Some(&v("1.3.0")), Some(&v("1.3.0"))),
            Outcome::Failed {
                running: "1.3.0".into()
            }
        );
    }

    /// A stand-in `smcpctl` (a shell script) shows that the passphrase
    /// reaches standard input and no argument, that progress lines arrive
    /// as they are printed, and that a rollback is reported as a failed
    /// upgrade with the version running afterwards.
    #[cfg(unix)]
    #[test]
    fn runs_smcpctl_upgrade_with_the_passphrase_on_stdin() {
        claims::partial(&["FR-20.12"]);
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("run");
        let bin = d.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = version ]; then cat "{state}"; exit 0; fi
echo "$@" > "{args}"
IFS= read -r pass
printf '%s' "$pass" > "{stdin}"
echo "upgrade: upgrading from 1.3.0 to 1.4.0"
if [ "$pass" = fail ]; then
  echo "upgrade: rolling back: the Gateway did not leave fail-closed within 1m0s (state fail-closed, version 1.4.0)"
  echo "smcpctl: upgrade rolled back: the Gateway did not leave fail-closed; the previous version is running" >&2
  exit 1
fi
echo 1.4.0 > "{state}"
echo "upgrade: upgrade complete"
"#,
            state = d.join("version").display(),
            args = d.join("args").display(),
            stdin = d.join("stdin").display(),
        );
        std::fs::write(bin.join("smcpctl"), script).unwrap();
        std::fs::set_permissions(bin.join("smcpctl"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(d.join("version"), "1.3.0\n").unwrap();
        let inst = Installation {
            bin_dir: bin.clone(),
            config: d.join("c.toml"),
        };
        let before = installed_version(&inst.smcpctl());
        assert_eq!(before, Some(Version::new(1, 3, 0)));

        // A failing upgrade that rolls back.
        let mut lines = Vec::new();
        let r = run_fixed(
            &upgrade_argv(&inst, &d.join("rel")),
            Some("fail"),
            Duration::from_secs(20),
            &mut |l| lines.push(l.to_string()),
        );
        assert_eq!(r.code, Some(1));
        assert!(lines.iter().any(|l| l.starts_with("upgrade: upgrading from")));
        let after = installed_version(&inst.smcpctl());
        assert_eq!(
            classify(&r, before.as_ref(), after.as_ref()),
            Outcome::RolledBack {
                running: "1.3.0".into()
            }
        );

        // A passphrase with spaces and shell characters is passed whole.
        let pass = "correct horse $(battery) 'staple'";
        let r = run_fixed(
            &upgrade_argv(&inst, &d.join("rel")),
            Some(pass),
            Duration::from_secs(20),
            &mut |_| {},
        );
        assert_eq!(r.code, Some(0), "{}", r.output);
        assert_eq!(std::fs::read_to_string(d.join("stdin")).unwrap(), pass);
        let args = std::fs::read_to_string(d.join("args")).unwrap();
        assert!(!args.contains("horse"), "the passphrase is in the arguments: {args}");
        assert!(args.contains("--passphrase-file -"));
        let after = installed_version(&inst.smcpctl());
        assert_eq!(
            classify(&r, before.as_ref(), after.as_ref()),
            Outcome::Upgraded {
                from: "1.3.0".into(),
                to: "1.4.0".into()
            }
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn run_fixed_kills_at_the_timeout_and_refuses_relative_programs() {
        claims::partial(&["FR-20.12"]);
        let r = run_fixed(
            &["/bin/sleep".into(), "5".into()],
            None,
            Duration::from_millis(200),
            &mut |_| {},
        );
        assert!(r.timed_out);
        let r = run_fixed(&["sleep".into(), "1".into()], None, Duration::from_secs(1), &mut |_| {});
        assert!(r.spawn_error.is_some());
    }
}
