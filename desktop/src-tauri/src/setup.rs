//! First-run setup (SRS FR-20.8, FR-20.9, FR-20.5, FR-20.19, SR-2-3,
//! SR-2-4, SR-2-7, F-103, I-42).
//!
//! The setup window is a front end to the terminal procedure, not a second
//! implementation of it: it collects the Administrator and Approver
//! passwords and runs `smcpctl install` for the chosen profile, which
//! performs the `smcpctl bootstrap` step (keys, TLS certificates,
//! configuration, policy and the two accounts) and then installs and starts
//! the service (FR-13.4 to FR-13.6). The passwords reach `smcpctl` only in
//! two files of mode 0600 in a private directory of mode 0700, which are
//! overwritten and deleted when the command ends; no password is ever in an
//! argument list. On Linux the Enforced profile is offered only after
//! `smcpctl install --profile enforced --check` reports every prerequisite
//! present, and its installation is the one step that asks for elevation
//! (`pkexec`, which names the command in its prompt).
//!
//! The application never reads the Gateway configuration (SR-2-3): it only
//! checks whether one exists.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::service::{self, Host};

/// FR-20.5: setup leaves metrics on at the CP-51 address, 127.0.0.1:9464,
/// which is the application's default metrics setting.
pub const METRICS_PORT: &str = "9464";
/// An installation pulls nothing from the network but waits up to 60 s for
/// the started Gateway; the Enforced profile also prepares the host.
pub const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// smcpctl's own bounds on an account password (bytes, as `len` in Go).
pub const MIN_PASSWORD_BYTES: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Output kept for the window: enough for the longest install.
const MAX_LINES: usize = 2000;
const MAX_LINE_CHARS: usize = 2000;
const PKEXEC: &str = "/usr/bin/pkexec";

/// A platform profile (FR-13.5, FR-13.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Standalone,
    Enforced,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Standalone => "standalone",
            Profile::Enforced => "enforced",
        }
    }
}

/// The configuration files `smcpctl install` writes on this host: the
/// Standalone file of CP-46 and the Enforced `/etc/smcp/smcp.toml`.
pub fn config_paths(h: &Host) -> Vec<PathBuf> {
    let mut v = Vec::new();
    match h.os {
        "macos" => v.push(h.home.join("Library/Application Support/smcp-gateway/config/smcp.toml")),
        "linux" => {
            let cfg = h.xdg_config_home.clone().unwrap_or_else(|| h.home.join(".config"));
            v.push(cfg.join("smcp-gateway/smcp.toml"));
            // etc_systemd is <etc>/systemd/system.
            if let Some(etc) = h.etc_systemd.parent().and_then(Path::parent) {
                v.push(etc.join("smcp/smcp.toml"));
            }
        }
        // The per-user and the machine mode (FR-21.6, CP-46).
        "windows" => {
            v.extend(h.win.user_config_dir().map(|d| config_file(&d)));
            v.extend(h.win.machine_config_dir().map(|d| config_file(&d)));
        }
        _ => {}
    }
    v
}

/// The Gateway configuration file in a Windows configuration directory
/// (named here only, SR-2-3; the application never reads it).
pub fn config_file(dir: &Path) -> PathBuf {
    dir.join("smcp.toml")
}

/// Whether a Gateway is already set up on this host: a configuration file
/// or a service unit exists. Only the files' existence is checked; a file
/// in a directory the user cannot search (the Enforced `/etc/smcp`) counts
/// as existing.
pub fn configured(h: &Host) -> bool {
    config_paths(h).iter().any(|p| present(p)) || service::detect(h).is_some()
}

/// Whether a file exists, counting one in a directory the user cannot
/// search (the Enforced `/etc/smcp`, root:smcp 0750) as existing.
pub fn present(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

/// The places `smcpctl` is looked for, in order: beside the application's
/// executable (the `.dmg`, the AppImage and the `smcp-desktop` `.msi`
/// bundle it there), then where the `.pkg`, the Linux packages, Homebrew
/// and `install.sh` put it, and on Windows where the `smcp` `.msi` and
/// `install.ps1` put it. Fixed at build time except for the directories
/// named by the environment; never PATH.
pub fn smcpctl_candidates(exe_dir: Option<&Path>, h: &Host) -> Vec<PathBuf> {
    let name = if h.os == "windows" { "smcpctl.exe" } else { "smcpctl" };
    let mut v = Vec::new();
    if let Some(d) = exe_dir {
        v.push(d.join(name));
    }
    if h.os != "windows" {
        for d in ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"] {
            v.push(Path::new(d).join(name));
        }
        v.push(h.home.join(".local/bin").join(name));
    } else {
        v.extend(h.win.machine_smcpctl());
        v.extend(
            h.win
                .local_app_data
                .as_ref()
                .map(|d| d.join("Programs").join("smcp-gateway").join(name)),
        );
    }
    v
}

pub fn find_smcpctl(exe_dir: Option<&Path>, h: &Host) -> Option<PathBuf> {
    smcpctl_candidates(exe_dir, h)
        .into_iter()
        .find(|p| p.is_absolute() && p.is_file())
}

/// The `smcpctl` that `pkexec` may run as root for the Enforced profile
/// (SR-2-7): `p` with every symbolic link resolved, provided that the file
/// and each directory above it are owned by root and writable by no one
/// else (group write only for group root). Otherwise a process of the user
/// could replace the file, or a directory on its path, between the check
/// and the polkit prompt and have its own program run as root; this
/// happens when the application runs from a build or download directory
/// and smcpctl is found in `~/.local/bin` (security review v1.3, SR-18).
#[cfg(unix)]
pub fn elevation_safe(p: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    let real = std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut cur = Some(real.as_path());
    while let Some(c) = cur {
        let m = std::fs::symlink_metadata(c).map_err(|e| format!("{}: {e}", c.display()))?;
        if m.uid() != 0 {
            return Err(format!("{} is not owned by root", c.display()));
        }
        let mode = m.mode();
        if mode & 0o002 != 0 || (mode & 0o020 != 0 && m.gid() != 0) {
            return Err(format!("{} can be changed by accounts other than root", c.display()));
        }
        cur = c.parent();
    }
    Ok(real)
}

/// Elevation is used on Linux only; elsewhere nothing qualifies.
#[cfg(not(unix))]
pub fn elevation_safe(p: &Path) -> Result<PathBuf, String> {
    Err(format!("{} cannot be run with elevation on this platform", p.display()))
}

/// The profiles setup may offer on this host (FR-20.9, FR-20.19): the
/// Enforced profile only on Linux and never from an AppImage, which cannot
/// install system packages.
pub fn profiles(os: &str, appimage: bool) -> Vec<Profile> {
    if os == "linux" && !appimage {
        vec![Profile::Standalone, Profile::Enforced]
    } else {
        vec![Profile::Standalone]
    }
}

/// What first-run setup would offer on this host, one `<key>\t<value>`
/// line each: `profile` for every profile of [`profiles`], `smcpctl` for
/// the command setup runs (or `not found`), and `configured` (`yes` or
/// `no`, [`configured`]). For `smcp-desktop --setup-profiles`, which the
/// installer smoke tests run to check that an AppImage offers the
/// Standalone profile only (FR-20.19). It runs nothing.
pub fn report(h: &Host, appimage: bool, exe_dir: Option<&Path>) -> Vec<String> {
    let mut v: Vec<String> = profiles(h.os, appimage)
        .into_iter()
        .map(|p| format!("profile\t{}", p.as_str()))
        .collect();
    v.push(match find_smcpctl(exe_dir, h) {
        Some(p) => format!("smcpctl\t{}", p.display()),
        None => "smcpctl\tnot found".into(),
    });
    v.push(format!("configured\t{}", if configured(h) { "yes" } else { "no" }));
    v
}

/// `smcp-desktop --setup-profiles`: prints [`report`] for this host and
/// returns the exit code (1 when no `smcpctl` was found).
pub fn print_report() -> i32 {
    let exe = std::env::current_exe().ok().map(|e| crate::commands::real_path(&e));
    let lines = report(
        &Host::current(),
        std::env::var_os("APPIMAGE").is_some(),
        exe.as_deref().and_then(Path::parent),
    );
    let found = !lines.iter().any(|l| l == "smcpctl\tnot found");
    for l in lines {
        println!("{l}");
    }
    if found {
        0
    } else {
        1
    }
}

/// The prerequisite check of FR-13.5, run as the user before Enforced is
/// offered. It changes nothing.
pub fn check_argv(smcpctl: &Path) -> Vec<String> {
    vec![
        smcpctl.display().to_string(),
        "install".into(),
        "--profile".into(),
        "enforced".into(),
        "--check".into(),
    ]
}

/// The outcome of the prerequisite check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", tag = "result")]
pub enum Check {
    /// Every prerequisite is present.
    Present,
    /// The prerequisites `smcpctl` named as missing.
    Missing { missing: Vec<String> },
    /// The check did not run or said nothing usable.
    Failed { detail: String },
}

pub fn parse_check(r: &service::RunResult) -> Check {
    if let Some(e) = &r.spawn_error {
        return Check::Failed { detail: e.clone() };
    }
    if r.timed_out {
        return Check::Failed {
            detail: format!("The check did not finish within {} seconds.", CHECK_TIMEOUT.as_secs()),
        };
    }
    if r.code == Some(0) {
        return Check::Present;
    }
    let missing: Vec<String> = r
        .stdout
        .lines()
        .chain(r.stderr.lines())
        .filter_map(|l| l.strip_prefix("  - "))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if missing.is_empty() {
        Check::Failed {
            detail: format!("{}{}", r.stdout, r.stderr).trim().to_string(),
        }
    } else {
        Check::Missing { missing }
    }
}

/// The installation command. The passwords are in files; the argument list
/// holds only their paths. Only the Enforced profile, a system-wide
/// service, runs elevated (SR-2-7).
pub fn install_argv(smcpctl: &Path, profile: Profile, files: &SecretFiles) -> Vec<String> {
    let mut v = Vec::new();
    if profile == Profile::Enforced {
        v.push(PKEXEC.to_string());
    }
    v.extend([
        smcpctl.display().to_string(),
        "install".into(),
        "--profile".into(),
        profile.as_str().into(),
        "--admin-password-file".into(),
        files.admin.display().to_string(),
        "--approver-password-file".into(),
        files.approver.display().to_string(),
        "--metrics-port".into(),
        METRICS_PORT.into(),
        // The desktop application raises the approval notifications
        // (FR-20.7); smcpd's own would duplicate them.
        "--notify".into(),
        "off".into(),
    ]);
    v
}

/// The command a user can run in a terminal to retry a failed step. It
/// prompts for the passwords instead of reading files.
pub fn retry_command(profile: Profile) -> String {
    match profile {
        Profile::Standalone => {
            format!("smcpctl install --profile standalone --metrics-port {METRICS_PORT} --notify off")
        }
        Profile::Enforced => format!("sudo smcpctl install --profile enforced --metrics-port {METRICS_PORT}"),
    }
}

/// A password from the setup window. It is never printed, and its memory is
/// overwritten when it is dropped.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8, so the String stays valid.
        unsafe { self.0.as_bytes_mut() }.fill(0);
    }
}

/// A rejected password, by role and message-catalogue code (FR-20.47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PasswordError {
    pub role: &'static str,
    pub code: &'static str,
}

/// smcpctl's password rules, checked before anything runs.
pub fn validate(admin: &Secret, approver: &Secret) -> Result<(), Vec<PasswordError>> {
    let mut errs = Vec::new();
    for (role, s) in [("admin", admin), ("approver", approver)] {
        let p = s.expose();
        if p.len() < MIN_PASSWORD_BYTES {
            errs.push(PasswordError {
                role,
                code: "SETUP_PASSWORD_TOO_SHORT",
            });
        } else if p.len() > MAX_PASSWORD_BYTES || p.contains(['\r', '\n', '\0']) {
            errs.push(PasswordError {
                role,
                code: "SETUP_PASSWORD_INVALID",
            });
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// The two password files of FR-20.8 in a new private directory. Dropping
/// the value overwrites and deletes them.
#[derive(Debug)]
pub struct SecretFiles {
    pub dir: PathBuf,
    pub admin: PathBuf,
    pub approver: PathBuf,
}

fn unique_name() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    h.write_u32(std::process::id());
    format!("smcp-setup-{:016x}", h.finish())
}

fn write_private(p: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    // create_new: never write through a file or link someone placed there.
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p)?;
    f.write_all(body)?;
    f.sync_all()
}

impl SecretFiles {
    /// Creates `<base>/smcp-setup-<random>/` (mode 0700) holding `admin`
    /// and `approver` (mode 0600), each with its password and no newline.
    pub fn create(base: &Path, admin: &Secret, approver: &Secret) -> std::io::Result<SecretFiles> {
        let dir = base.join(unique_name());
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        // Not recursive: fails if the name exists.
        b.create(&dir)?;
        let files = SecretFiles {
            admin: dir.join("admin"),
            approver: dir.join("approver"),
            dir,
        };
        write_private(&files.admin, admin.expose().as_bytes())?;
        write_private(&files.approver, approver.expose().as_bytes())?;
        Ok(files)
    }
}

impl Drop for SecretFiles {
    fn drop(&mut self) {
        for p in [&self.admin, &self.approver] {
            if let Ok(m) = std::fs::metadata(p) {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .open(p)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, &vec![0u8; m.len() as usize]));
            }
            let _ = std::fs::remove_file(p);
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Where a running setup is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RunState {
    Idle,
    Running,
    Succeeded,
    Failed,
}

/// A failed setup, for the window: the catalogue code, the command to run
/// in a terminal, and a plain explanation of how the command ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    pub code: &'static str,
    pub retry: String,
    pub detail: String,
}

/// The setup's progress, which the window polls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub state: RunState,
    pub profile: Option<Profile>,
    /// The bootstrap step (keys, certificates, configuration, policy) has
    /// reported its result; the service step follows.
    pub bootstrap_done: bool,
    pub service_done: bool,
    pub output: Vec<String>,
    pub failure: Option<Failure>,
    /// The bundled ContextForge choice (FR-22.44, contextforge.rs).
    pub contextforge: bool,
}

impl Default for Progress {
    fn default() -> Self {
        Progress {
            state: RunState::Idle,
            profile: None,
            bootstrap_done: false,
            service_done: false,
            output: Vec::new(),
            failure: None,
            contextforge: false,
        }
    }
}

impl Progress {
    pub fn start(profile: Profile) -> Progress {
        Progress {
            state: RunState::Running,
            profile: Some(profile),
            ..Default::default()
        }
    }

    /// Records one output line of `smcpctl install` and follows its steps:
    /// the bootstrap step ends with its `configuration` line, the service
    /// step with the health check's `healthy`/`degraded` report or the
    /// skipped start.
    pub fn line(&mut self, line: &str) {
        let line: String = line.chars().take(MAX_LINE_CHARS).collect();
        let step = line.split_once(' ');
        if let Some((verb, what)) = step {
            if matches!(verb, "created" | "present" | "updated") && what.starts_with("configuration ") {
                self.bootstrap_done = true;
            }
            if self.bootstrap_done
                && (line.starts_with("This installation is not enforced")
                    || line.starts_with("Enforced profile installed"))
            {
                self.service_done = true;
            }
        }
        if self.output.len() < MAX_LINES {
            self.output.push(line);
        } else if self.output.len() == MAX_LINES {
            self.output.push("(further output not shown)".into());
        }
    }

    /// Records how the command ended.
    pub fn finish(&mut self, exit: &Exit) {
        let profile = self.profile.unwrap_or(Profile::Standalone);
        if exit.code == Some(0) && exit.spawn_error.is_none() && !exit.timed_out {
            self.state = RunState::Succeeded;
            self.bootstrap_done = true;
            self.service_done = true;
            return;
        }
        self.state = RunState::Failed;
        let retry = crate::contextforge::retry(retry_command(profile), self.contextforge);
        let (code, detail) = if let Some(e) = &exit.spawn_error {
            ("SETUP_BOOTSTRAP_FAILED", format!("smcpctl could not be started: {e}"))
        } else if exit.timed_out {
            (
                if self.bootstrap_done {
                    "SETUP_INSTALL_FAILED"
                } else {
                    "SETUP_BOOTSTRAP_FAILED"
                },
                format!(
                    "smcpctl install did not finish within {} minutes and was stopped.",
                    INSTALL_TIMEOUT.as_secs() / 60
                ),
            )
        } else if profile == Profile::Enforced && matches!(exit.code, Some(126) | Some(127)) && self.output_is_empty() {
            (
                "ELEVATION_DENIED",
                "pkexec ended without running smcpctl: the permission prompt was cancelled or refused.".into(),
            )
        } else {
            let status = exit
                .code
                .map(|c| format!("exited with status {c}"))
                .unwrap_or_else(|| "was stopped by a signal".into());
            (
                if self.bootstrap_done {
                    "SETUP_INSTALL_FAILED"
                } else {
                    "SETUP_BOOTSTRAP_FAILED"
                },
                format!(
                    "smcpctl install {status}, which means it stopped at an error. Its output below names the cause."
                ),
            )
        };
        self.failure = Some(Failure { code, retry, detail });
    }

    fn output_is_empty(&self) -> bool {
        self.output
            .iter()
            .all(|l| l.trim().is_empty() || l.contains("pkexec") || l.contains("Not authorized"))
    }
}

/// How a streamed command ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exit {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub spawn_error: Option<String>,
}

/// Runs a fixed argument vector with no shell and a closed standard input,
/// passing each line of standard output and standard error to `on_line` as
/// it arrives, and kills it at the timeout.
pub fn run_streaming(argv: &[String], timeout: Duration, on_line: Arc<dyn Fn(&str) + Send + Sync>) -> Exit {
    run_streaming_in(argv, None, timeout, on_line)
}

/// [`run_streaming`] with a working directory.
pub fn run_streaming_in(
    argv: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
    on_line: Arc<dyn Fn(&str) + Send + Sync>,
) -> Exit {
    let Some((prog, args)) = argv.split_first() else {
        return Exit {
            spawn_error: Some("empty command".into()),
            ..Default::default()
        };
    };
    let mut cmd = Command::new(prog);
    service::no_console(&mut cmd);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    let child = cmd.spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return Exit {
                spawn_error: Some(format!("{prog}: {e}")),
                ..Default::default()
            }
        }
    };
    let readers: Vec<_> = [
        child.stdout.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
        child.stderr.take().map(|p| Box::new(p) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|p| {
        let cb = on_line.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(p).lines() {
                match line {
                    Ok(l) => cb(&l),
                    Err(_) => break,
                }
            }
        })
    })
    .collect();
    let start = Instant::now();
    let exit = loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                break Exit {
                    code: st.code(),
                    ..Default::default()
                }
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break Exit {
                    timed_out: true,
                    ..Default::default()
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                break Exit {
                    spawn_error: Some(e.to_string()),
                    ..Default::default()
                }
            }
        }
    };
    for r in readers {
        let _ = r.join();
    }
    exit
}

/// One setup at a time, shared by the window's commands.
#[derive(Default)]
pub struct Session {
    pub progress: Mutex<Progress>,
    /// The last prerequisite check of the Enforced profile.
    pub enforced: Mutex<Option<Check>>,
}

impl Session {
    /// Marks a setup as running, so the window's next poll sees it. Returns
    /// false when one is already running.
    pub fn begin(&self, profile: Profile) -> bool {
        let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if p.state == RunState::Running {
            return false;
        }
        *p = Progress::start(profile);
        true
    }

    /// [`Session::begin`], then [`Session::execute`] on the calling thread.
    pub fn run(
        self: &Arc<Self>,
        smcpctl: &Path,
        profile: Profile,
        admin: Secret,
        approver: Secret,
        tmp: &Path,
    ) -> bool {
        if !self.begin(profile) {
            return false;
        }
        self.execute(smcpctl, profile, admin, approver, tmp);
        true
    }

    /// Runs the installation that [`Session::begin`] started, recording
    /// progress, and deletes the password files when the command ends.
    pub fn execute(self: &Arc<Self>, smcpctl: &Path, profile: Profile, admin: Secret, approver: Secret, tmp: &Path) {
        let files = SecretFiles::create(tmp, &admin, &approver);
        drop((admin, approver));
        let files = match files {
            Ok(f) => f,
            Err(e) => {
                let mut p = self.progress.lock().unwrap_or_else(|e| e.into_inner());
                p.finish(&Exit {
                    spawn_error: Some(format!("the password files could not be written: {e}")),
                    ..Default::default()
                });
                return;
            }
        };
        let chosen = self.progress.lock().unwrap_or_else(|e| e.into_inner()).contextforge;
        let argv = crate::contextforge::with_choice(install_argv(smcpctl, profile, &files), chosen);
        let me = self.clone();
        let exit = run_streaming(
            &argv,
            INSTALL_TIMEOUT,
            Arc::new(move |l: &str| me.progress.lock().unwrap_or_else(|e| e.into_inner()).line(l)),
        );
        // The command has ended: the files go before the result is shown.
        drop(files);
        self.progress.lock().unwrap_or_else(|e| e.into_inner()).finish(&exit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use crate::service::RunResult;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("smcp-desktop-setup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn host(os: &'static str, root: &Path) -> Host {
        Host {
            os,
            home: root.join("home"),
            xdg_config_home: None,
            etc_systemd: root.join("etc/systemd/system"),
            uid: 501,
            win: Default::default(),
        }
    }

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }

    #[test]
    fn offered_only_without_a_configuration() {
        claims::partial(&["FR-20.8", "SR-2-3"]);
        let root = tmp("configured");
        let mac = host("macos", &root);
        assert!(!configured(&mac));
        touch(&root.join("home/Library/Application Support/smcp-gateway/config/smcp.toml"));
        assert!(configured(&mac));

        let linux = host("linux", &root);
        assert!(!configured(&linux));
        touch(&root.join("etc/smcp/smcp.toml"));
        assert!(configured(&linux));
        std::fs::remove_dir_all(root.join("etc")).unwrap();
        touch(&root.join("home/.config/smcp-gateway/smcp.toml"));
        assert!(configured(&linux));
        std::fs::remove_dir_all(root.join("home/.config")).unwrap();
        // A service unit without the configuration still counts.
        touch(&root.join("home/.config/systemd/user/smcpd.service"));
        assert!(configured(&linux));

        // Windows: the per-user and the machine-mode configuration.
        let win = Host {
            os: "windows",
            win: crate::service::WinDirs {
                local_app_data: Some(root.join("Local")),
                program_data: Some(root.join("ProgramData")),
                ..Default::default()
            },
            ..host("windows", &root)
        };
        assert!(!configured(&win));
        touch(&root.join("Local/smcp-gateway/config/smcp.toml"));
        assert!(configured(&win));
        std::fs::remove_dir_all(root.join("Local")).unwrap();
        touch(&root.join("ProgramData/smcp-gateway/config/smcp.toml"));
        assert!(configured(&win));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The Enforced configuration sits in /etc/smcp (root:smcp 0750), which
    /// the user cannot search: client setup still finds it by path and
    /// passes it to smcpctl connect, which reads the client view instead.
    #[cfg(unix)]
    #[test]
    fn enforced_configuration_in_an_unsearchable_directory_is_found() {
        use std::os::unix::fs::PermissionsExt;
        claims::partial(&["FR-20.10"]);
        if unsafe { libc::geteuid() } == 0 {
            return; // root searches every directory
        }
        let root = tmp("unsearchable");
        let linux = host("linux", &root);
        let cfg = root.join("etc/smcp/smcp.toml");
        touch(&cfg);
        std::fs::set_permissions(root.join("etc/smcp"), std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(!cfg.exists(), "the test needs a directory this user cannot search");
        assert!(present(&cfg));
        assert_eq!(crate::clients::config_path(&linux), Some(cfg));
        std::fs::set_permissions(root.join("etc/smcp"), std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn smcpctl_is_found_in_fixed_places_only() {
        claims::partial(&["FR-20.8", "SR-2-5"]);
        let root = tmp("find");
        let h = host("linux", &root);
        let exe = root.join("app");
        let c = smcpctl_candidates(Some(&exe), &h);
        assert_eq!(c[0], exe.join("smcpctl"));
        assert!(c.contains(&PathBuf::from("/usr/bin/smcpctl")));
        assert!(c.contains(&PathBuf::from("/usr/local/bin/smcpctl")));
        assert!(c.iter().all(|p| p.is_absolute() || !cfg!(unix)));
        touch(&exe.join("smcpctl"));
        assert_eq!(find_smcpctl(Some(&exe), &h), Some(exe.join("smcpctl")));
        let w = Host {
            os: "windows",
            ..h.clone()
        };
        assert_eq!(smcpctl_candidates(Some(&exe), &w), vec![exe.join("smcpctl.exe")]);
        // Beside the app (smcp-desktop .msi), then the smcp .msi and
        // machine mode, then install.ps1; never PATH.
        let w = Host {
            win: crate::service::WinDirs {
                local_app_data: Some(root.join("Local")),
                program_files: Some(root.join("Program Files")),
                ..Default::default()
            },
            ..w
        };
        assert_eq!(
            smcpctl_candidates(Some(&exe), &w),
            vec![
                exe.join("smcpctl.exe"),
                root.join("Program Files").join("smcp-gateway").join("smcpctl.exe"),
                root.join("Local")
                    .join("Programs")
                    .join("smcp-gateway")
                    .join("smcpctl.exe"),
            ]
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn enforced_is_offered_on_linux_packages_only() {
        claims::partial(&["FR-20.9", "FR-20.19"]);
        assert_eq!(profiles("macos", false), vec![Profile::Standalone]);
        assert_eq!(profiles("windows", false), vec![Profile::Standalone]);
        assert_eq!(profiles("linux", false), vec![Profile::Standalone, Profile::Enforced]);
        assert_eq!(profiles("linux", true), vec![Profile::Standalone]);
    }

    #[test]
    fn the_setup_report_names_the_offered_profiles() {
        claims::partial(&["FR-20.19"]);
        let root = tmp("report");
        let exe = root.join("app");
        touch(&exe.join("smcpctl"));
        let linux = host("linux", &root);
        let r = report(&linux, true, Some(&exe));
        assert_eq!(
            r,
            vec![
                "profile\tstandalone".to_string(),
                format!("smcpctl\t{}", exe.join("smcpctl").display()),
                "configured\tno".to_string(),
            ]
        );
        let r = report(&linux, false, Some(&exe));
        assert_eq!(&r[..2], ["profile\tstandalone", "profile\tenforced"]);
        touch(&root.join("home/.config/smcp-gateway/smcp.toml"));
        assert_eq!(
            report(&linux, true, Some(&root.join("none"))).last().unwrap(),
            "configured\tyes"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_prerequisite_check_names_each_missing_one() {
        claims::partial(&["FR-20.9"]);
        assert_eq!(
            check_argv(Path::new("/usr/bin/smcpctl")),
            ["/usr/bin/smcpctl", "install", "--profile", "enforced", "--check"]
        );
        let ok = RunResult {
            code: Some(0),
            stdout: "install-enforced: all prerequisites present\n".into(),
            ..Default::default()
        };
        assert_eq!(parse_check(&ok), Check::Present);
        let missing = RunResult {
            code: Some(1),
            stdout: "install-enforced: prerequisites missing; nothing was changed:\n  - podman\n  - newuidmap (uidmap package)\n"
                .into(),
            stderr: "smcpctl: Enforced profile prerequisites are missing (listed above); nothing was changed\n".into(),
            ..Default::default()
        };
        assert_eq!(
            parse_check(&missing),
            Check::Missing {
                missing: vec!["podman".into(), "newuidmap (uidmap package)".into()]
            }
        );
        let odd = RunResult {
            code: Some(2),
            stderr: "flag provided but not defined: -check\n".into(),
            ..Default::default()
        };
        assert!(matches!(parse_check(&odd), Check::Failed { detail } if detail.contains("-check")));
        assert!(matches!(
            parse_check(&RunResult {
                timed_out: true,
                ..Default::default()
            }),
            Check::Failed { .. }
        ));
    }

    #[test]
    fn passwords_go_in_private_files_never_in_arguments() {
        claims::partial(&["FR-20.8", "SR-2-4", "SR-2-7", "FR-20.5"]);
        let base = tmp("files");
        let admin = Secret::new("correct horse battery");
        let approver = Secret::new("approver staple 42");
        let files = SecretFiles::create(&base, &admin, &approver).unwrap();
        assert_eq!(std::fs::read_to_string(&files.admin).unwrap(), "correct horse battery");
        assert_eq!(std::fs::read_to_string(&files.approver).unwrap(), "approver staple 42");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&files.dir), 0o700);
            assert_eq!(mode(&files.admin), 0o600);
            assert_eq!(mode(&files.approver), 0o600);
        }
        let smcpctl = Path::new("/usr/bin/smcpctl");
        for profile in [Profile::Standalone, Profile::Enforced] {
            let argv = install_argv(smcpctl, profile, &files);
            for a in &argv {
                assert!(!a.contains("correct horse") && !a.contains("staple"), "{a}");
            }
            let joined = argv.join(" ");
            assert!(joined.contains(&format!("--admin-password-file {}", files.admin.display())));
            assert!(joined.contains(&format!("--approver-password-file {}", files.approver.display())));
            assert!(joined.contains(&format!("--profile {}", profile.as_str())));
            // FR-20.5: metrics on the CP-51 address.
            assert!(joined.contains("--metrics-port 9464"));
            // SR-2-7: elevation only for the system-wide service.
            assert_eq!(argv[0] == "/usr/bin/pkexec", profile == Profile::Enforced, "{joined}");
            assert!(!joined.contains("sudo"));
        }
        let dir = files.dir.clone();
        let paths = (files.admin.clone(), files.approver.clone());
        drop(files);
        assert!(!paths.0.exists() && !paths.1.exists() && !dir.exists());
        // The Debug form never shows the password.
        assert_eq!(format!("{admin:?}"), "Secret(redacted)");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Security review v1.3, SR-18: pkexec runs smcpctl as root only from
    /// a path the user cannot change. A copy in a directory the user owns
    /// (as `~/.local/bin` is), or a link to one, is refused; a root-owned
    /// system file is accepted with its links resolved.
    #[cfg(unix)]
    #[test]
    fn elevation_only_runs_a_root_owned_smcpctl() {
        claims::partial(&["SR-2-7", "FR-20.9"]);
        let root = tmp("elevation");
        let user_copy = root.join("home/.local/bin/smcpctl");
        touch(&user_copy);
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            let err = elevation_safe(&user_copy).unwrap_err();
            assert!(err.contains("not owned by root"), "{err}");
            let link = root.join("smcpctl-link");
            std::os::unix::fs::symlink(&user_copy, &link).unwrap();
            assert!(elevation_safe(&link).is_err());
        }
        assert!(elevation_safe(&root.join("missing")).is_err());
        // A file owned by root in root-owned directories: /bin/sh exists on
        // every Unix test host (on some, /bin is a link to /usr/bin).
        let sh = elevation_safe(Path::new("/bin/sh")).unwrap();
        assert!(sh.is_absolute());
        assert_eq!(sh, std::fs::canonicalize("/bin/sh").unwrap());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn passwords_follow_smcpctl_rules() {
        claims::partial(&["FR-20.8", "FR-20.47"]);
        let s = Secret::new;
        assert_eq!(validate(&s("twelve chars"), &s("another12345")), Ok(()));
        assert_eq!(
            validate(&s("short"), &s("line\nbreak in it")).unwrap_err(),
            vec![
                PasswordError {
                    role: "admin",
                    code: "SETUP_PASSWORD_TOO_SHORT"
                },
                PasswordError {
                    role: "approver",
                    code: "SETUP_PASSWORD_INVALID"
                }
            ]
        );
        assert!(validate(&Secret::new("x".repeat(1025)), &s("long enough pw")).is_err());
    }

    #[test]
    fn progress_follows_the_two_steps_and_explains_failures() {
        claims::partial(&["FR-20.8", "FR-20.47"]);
        let mut p = Progress::start(Profile::Standalone);
        p.line("created directory /home/u/.config/smcp-gateway");
        p.line("created keys and TLS certificates in /home/u/.local/state/smcp-gateway");
        assert!(!p.bootstrap_done);
        p.line("created configuration /home/u/.config/smcp-gateway/smcp.toml");
        assert!(p.bootstrap_done && !p.service_done);
        p.line("created service unit /home/u/.config/systemd/user/smcpd.service");
        p.finish(&Exit {
            code: Some(1),
            ..Default::default()
        });
        let f = p.failure.clone().unwrap();
        assert_eq!(p.state, RunState::Failed);
        assert_eq!(f.code, "SETUP_INSTALL_FAILED");
        assert_eq!(
            f.retry,
            "smcpctl install --profile standalone --metrics-port 9464 --notify off"
        );
        // No bare exit status: it comes with what it means.
        assert!(f.detail.contains("exited with status 1, which means"), "{}", f.detail);

        let mut p = Progress::start(Profile::Standalone);
        p.line("smcpctl: administrator password must be at least 12 characters");
        p.finish(&Exit {
            code: Some(1),
            ..Default::default()
        });
        assert_eq!(p.failure.unwrap().code, "SETUP_BOOTSTRAP_FAILED");

        let mut p = Progress::start(Profile::Enforced);
        p.finish(&Exit {
            code: Some(126),
            ..Default::default()
        });
        let f = p.failure.unwrap();
        assert_eq!(f.code, "ELEVATION_DENIED");
        assert_eq!(f.retry, "sudo smcpctl install --profile enforced --metrics-port 9464");

        let mut p = Progress::start(Profile::Standalone);
        p.finish(&Exit {
            timed_out: true,
            ..Default::default()
        });
        assert!(p.failure.unwrap().detail.contains("15 minutes"));

        let mut p = Progress::start(Profile::Standalone);
        for i in 0..(MAX_LINES + 10) {
            p.line(&format!("line {i}"));
        }
        assert_eq!(p.output.len(), MAX_LINES + 1);
        p.finish(&Exit {
            code: Some(0),
            ..Default::default()
        });
        assert_eq!(p.state, RunState::Succeeded);
        assert!(p.failure.is_none());
    }

    /// A fake smcpctl that records its arguments and the password files'
    /// modes and contents, then prints install-like steps.
    #[cfg(unix)]
    fn fake_smcpctl(dir: &Path, exit: i32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("smcpctl");
        let script = format!(
            r#"#!/bin/sh
log="{log}"
echo "$@" > "$log"
while [ $# -gt 0 ]; do
  case "$1" in
    --admin-password-file|--approver-password-file)
      stat -c '%a' "$2" >> "$log" 2>/dev/null || stat -f '%Lp' "$2" >> "$log"
      cat "$2" >> "$log"; echo >> "$log"; shift ;;
  esac
  shift
done
echo "created keys and TLS certificates in /x/state"
echo "created configuration /x/smcp.toml"
echo "boom" >&2
exit {exit}
"#,
            log = dir.join("log").display()
        );
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn a_run_passes_files_streams_output_and_deletes_the_files() {
        claims::partial(&["FR-20.8", "SR-2-4"]);
        let dir = tmp("run");
        let smcpctl = fake_smcpctl(&dir, 0);
        let s = Arc::new(Session::default());
        assert!(s.run(
            &smcpctl,
            Profile::Standalone,
            Secret::new("admin password 1"),
            Secret::new("approver password 2"),
            &dir,
        ));
        let p = s.progress.lock().unwrap().clone();
        assert_eq!(p.state, RunState::Succeeded, "{p:?}");
        assert!(p.output.iter().any(|l| l == "boom"), "stderr is shown: {:?}", p.output);
        let log = std::fs::read_to_string(dir.join("log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert!(lines[0].starts_with("install --profile standalone --admin-password-file "));
        assert!(!lines[0].contains("admin password 1"));
        assert_eq!(&lines[1..], ["600", "admin password 1", "600", "approver password 2"]);
        // Nothing is left of the password files.
        let left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("smcp-setup-"))
            .collect();
        assert!(left.is_empty(), "{left:?}");

        // A failing command is reported with its output.
        let smcpctl = fake_smcpctl(&dir, 3);
        assert!(s.run(
            &smcpctl,
            Profile::Standalone,
            Secret::new("admin password 1"),
            Secret::new("approver password 2"),
            &dir,
        ));
        let p = s.progress.lock().unwrap().clone();
        assert_eq!(p.state, RunState::Failed);
        assert_eq!(p.failure.unwrap().code, "SETUP_INSTALL_FAILED");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
