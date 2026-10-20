//! Service control through the platform service manager (SRS FR-20.3,
//! SR-2-7, X-07).
//!
//! The application starts, stops and restarts the `smcpd` service that
//! `smcpctl install` created, and only through the service manager: the
//! launchd user agent `com.smcp.gateway` on macOS, the systemd user unit
//! `smcpd.service` or, for the Enforced profile, the system unit of the
//! same name on Linux. Every command is a fixed argument vector with an
//! absolute program path; nothing comes from the user, the Gateway or the
//! console. Elevation (`pkexec`, which names the command in its polkit
//! prompt) is requested only for the system unit. The names mirror
//! `cmd/smcpctl/service.go`.
//!
//! On Windows (FR-21.6) the application runs `smcpctl service
//! start|stop|restart|status --config <file>` instead, which holds the
//! per-user stop event, supervisor start and Service Control Manager calls:
//! for the per-user installation as the user, and for the machine-mode
//! service `smcpd` with the User Account Control prompt (`winproc`), the
//! only elevation, using the `smcpctl.exe` that `smcpctl install --machine`
//! placed in `%ProgramFiles%\smcp-gateway`, which only administrators can
//! change. The status query is never elevated.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::state::ServiceStatus;

pub const LAUNCHD_LABEL: &str = "com.smcp.gateway";
pub const SYSTEMD_UNIT: &str = "smcpd.service";
pub const NFT_UNIT: &str = "smcp-nftables.service";
/// FR-20.3: the outcome is reported within 30 seconds.
pub const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Status queries run every poll; they must be quick.
pub const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

const LAUNCHCTL: &str = "/bin/launchctl";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PKEXEC: &str = "/usr/bin/pkexec";

/// The service manager that runs the installed `smcpd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Manager {
    /// macOS launchd user agent, with the user's ID and the agent's plist.
    Launchd { uid: u32, plist: PathBuf },
    /// Linux systemd user unit (Standalone).
    SystemdUser,
    /// Linux systemd system unit (Enforced); changes need elevation.
    SystemdSystem,
    /// Windows per-user installation (Task Scheduler task or Run value),
    /// controlled through `smcpctl service` as the user.
    WindowsUser { smcpctl: PathBuf, config: PathBuf },
    /// Windows machine-mode service `smcpd`; changes need User Account
    /// Control.
    WindowsMachine { smcpctl: PathBuf, config: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    pub fn verb(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
        }
    }
}

/// Where the unit files are; tests point these at a temporary directory.
#[derive(Debug, Clone)]
pub struct Host {
    pub os: &'static str,
    pub home: PathBuf,
    pub xdg_config_home: Option<PathBuf>,
    pub etc_systemd: PathBuf,
    pub uid: u32,
    /// The Windows directories (used on Windows only).
    pub win: WinDirs,
}

/// The Windows directories of CP-46 and the application's own directory,
/// from the environment (`LOCALAPPDATA`, `ProgramData`, `ProgramFiles`).
#[derive(Debug, Clone, Default)]
pub struct WinDirs {
    pub local_app_data: Option<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub program_files: Option<PathBuf>,
    /// The directory of the application's executable.
    pub exe_dir: Option<PathBuf>,
}

impl WinDirs {
    pub fn current() -> WinDirs {
        let env = |k: &str| std::env::var_os(k).map(PathBuf::from).filter(|p| p.is_absolute());
        WinDirs {
            local_app_data: env("LOCALAPPDATA"),
            program_data: env("ProgramData"),
            program_files: env("ProgramFiles"),
            exe_dir: std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(Path::to_path_buf)),
        }
    }

    /// The per-user configuration directory (`smcpctl install`).
    pub fn user_config_dir(&self) -> Option<PathBuf> {
        self.local_app_data
            .as_ref()
            .map(|d| d.join("smcp-gateway").join("config"))
    }

    /// The per-user state directory.
    pub fn user_state_dir(&self) -> Option<PathBuf> {
        self.local_app_data
            .as_ref()
            .map(|d| d.join("smcp-gateway").join("state"))
    }

    /// The machine-mode configuration directory (`smcpctl install --machine`).
    pub fn machine_config_dir(&self) -> Option<PathBuf> {
        self.program_data
            .as_ref()
            .map(|d| d.join("smcp-gateway").join("config"))
    }

    /// The machine-mode binaries, which only administrators can change.
    pub fn machine_smcpctl(&self) -> Option<PathBuf> {
        self.program_files
            .as_ref()
            .map(|d| d.join("smcp-gateway").join("smcpctl.exe"))
    }
}

/// The definition files `smcpctl install` writes beside the configuration
/// (cmd/smcpctl/install_winuser.go).
pub const WIN_TASK_FILE: &str = "smcpd-task.xml";
pub const WIN_RUN_FILE: &str = "smcpd-run.txt";
pub const WIN_SERVICE_FILE: &str = "smcpd-service.txt";

impl Host {
    pub fn current() -> Host {
        // Windows sets USERPROFILE, not HOME.
        let home = std::env::var_os("HOME")
            .or_else(|| cfg!(windows).then(|| std::env::var_os("USERPROFILE")).flatten())
            .map(PathBuf::from)
            .unwrap_or_default();
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        Host {
            os: std::env::consts::OS,
            home,
            xdg_config_home: xdg,
            etc_systemd: PathBuf::from("/etc/systemd/system"),
            uid: current_uid(),
            win: WinDirs::current(),
        }
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Finds the installed service, in the order `smcpctl` uses.
pub fn detect(h: &Host) -> Option<Manager> {
    match h.os {
        "macos" => {
            let plist = h
                .home
                .join("Library/LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist"));
            plist.is_file().then_some(Manager::Launchd { uid: h.uid, plist })
        }
        "linux" => {
            let cfg = h.xdg_config_home.clone().unwrap_or_else(|| h.home.join(".config"));
            if cfg.join("systemd/user").join(SYSTEMD_UNIT).is_file() {
                Some(Manager::SystemdUser)
            } else if h.etc_systemd.join(SYSTEMD_UNIT).is_file() {
                Some(Manager::SystemdSystem)
            } else {
                None
            }
        }
        "windows" => detect_windows(h),
        _ => None,
    }
}

/// A file that exists, or that the user may not see (the machine-mode
/// configuration directory grants users no access).
fn exists_or_hidden(p: &Path) -> bool {
    match std::fs::symlink_metadata(p) {
        Ok(_) => true,
        Err(e) => e.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

fn detect_windows(h: &Host) -> Option<Manager> {
    if let Some(dir) = h.win.user_config_dir() {
        if dir.join(WIN_TASK_FILE).is_file() || dir.join(WIN_RUN_FILE).is_file() {
            let smcpctl = crate::setup::find_smcpctl(h.win.exe_dir.as_deref(), h)?;
            return Some(Manager::WindowsUser {
                smcpctl,
                config: crate::setup::config_file(&dir),
            });
        }
    }
    let dir = h.win.machine_config_dir()?;
    if exists_or_hidden(&dir.join(WIN_SERVICE_FILE)) {
        let smcpctl = h.win.machine_smcpctl().filter(|p| p.is_file())?;
        return Some(Manager::WindowsMachine {
            smcpctl,
            config: crate::setup::config_file(&dir),
        });
    }
    None
}

/// Whether actions on this service run with the User Account Control
/// prompt (Windows machine mode). On Linux the system unit's commands
/// carry `pkexec` themselves.
pub fn needs_uac(m: &Manager) -> bool {
    matches!(m, Manager::WindowsMachine { .. })
}

/// `smcpctl service <verb> --config <file>`.
fn smcpctl_service(smcpctl: &Path, verb: &str, config: &Path) -> Vec<String> {
    vec![
        smcpctl.display().to_string(),
        "service".into(),
        verb.into(),
        "--config".into(),
        config.display().to_string(),
    ]
}

/// Joins arguments into one Windows command line by the Microsoft C
/// runtime rules (as Go's `windows.ComposeCommandLine` does), for
/// `ShellExecuteExW`.
pub fn windows_command_line(args: &[String]) -> String {
    let mut out = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if !a.is_empty() && !a.contains([' ', '\t', '\n', '\x0b', '"']) {
            out.push_str(a);
            continue;
        }
        out.push('"');
        let mut backslashes = 0;
        for c in a.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    out.extend(std::iter::repeat_n('\\', backslashes));
                    out.push(c);
                    backslashes = 0;
                }
            }
        }
        out.extend(std::iter::repeat_n('\\', backslashes * 2));
        out.push('"');
    }
    out
}

/// Keeps a console program started by the application from opening a
/// console window on Windows (CREATE_NO_WINDOW); does nothing elsewhere.
pub fn no_console(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    cmd
}

fn v(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

/// The argument vector of an action. The first element is an absolute path.
pub fn action_argv(m: &Manager, a: Action) -> Vec<String> {
    match m {
        Manager::Launchd { uid, plist } => {
            let domain = format!("gui/{uid}");
            let target = format!("{domain}/{LAUNCHD_LABEL}");
            match a {
                Action::Start => vec![
                    LAUNCHCTL.into(),
                    "bootstrap".into(),
                    domain,
                    plist.display().to_string(),
                ],
                Action::Stop => vec![LAUNCHCTL.into(), "bootout".into(), target],
                Action::Restart => vec![LAUNCHCTL.into(), "kickstart".into(), "-k".into(), target],
            }
        }
        Manager::SystemdUser => v(&[SYSTEMCTL, "--user", a.verb(), SYSTEMD_UNIT]),
        Manager::SystemdSystem => match a {
            // As smcpctl does: the nftables unit starts with the Gateway.
            Action::Start => v(&[PKEXEC, SYSTEMCTL, "start", NFT_UNIT, SYSTEMD_UNIT]),
            _ => v(&[PKEXEC, SYSTEMCTL, a.verb(), SYSTEMD_UNIT]),
        },
        Manager::WindowsUser { smcpctl, config } | Manager::WindowsMachine { smcpctl, config } => {
            smcpctl_service(smcpctl, a.verb(), config)
        }
    }
}

/// The argument vector of the status query (never elevated).
pub fn status_argv(m: &Manager) -> Vec<String> {
    match m {
        Manager::Launchd { uid, .. } => vec![LAUNCHCTL.into(), "print".into(), format!("gui/{uid}/{LAUNCHD_LABEL}")],
        Manager::SystemdUser => v(&[SYSTEMCTL, "--user", "is-active", SYSTEMD_UNIT]),
        Manager::SystemdSystem => v(&[SYSTEMCTL, "is-active", SYSTEMD_UNIT]),
        Manager::WindowsUser { smcpctl, config } | Manager::WindowsMachine { smcpctl, config } => {
            smcpctl_service(smcpctl, "status", config)
        }
    }
}

/// Reads the status query's result.
pub fn parse_status(m: &Manager, r: &RunResult) -> ServiceStatus {
    if r.timed_out || r.spawn_error.is_some() {
        return ServiceStatus::Unknown;
    }
    match m {
        // `launchctl print` succeeds while the agent is loaded (KeepAlive
        // restarts it if it exits) and fails once it is booted out.
        Manager::Launchd { .. } => {
            if r.code == Some(0) {
                ServiceStatus::Running
            } else {
                ServiceStatus::Stopped
            }
        }
        Manager::SystemdUser | Manager::SystemdSystem => match r.stdout.trim() {
            "active" | "activating" | "reloading" | "refreshing" => ServiceStatus::Running,
            "inactive" | "failed" | "deactivating" => ServiceStatus::Stopped,
            _ => ServiceStatus::Unknown,
        },
        // `smcpctl service status` prints one word.
        Manager::WindowsUser { .. } | Manager::WindowsMachine { .. } => match (r.code, r.stdout.trim()) {
            (Some(0), "running") => ServiceStatus::Running,
            (Some(0), "stopped") => ServiceStatus::Stopped,
            (Some(0), "not-installed") => ServiceStatus::NotInstalled,
            _ => ServiceStatus::Unknown,
        },
    }
}

/// The result of running one command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunResult {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub spawn_error: Option<String>,
}

/// Runs a fixed argument vector. A trait so tests can record commands.
pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String], timeout: Duration) -> RunResult;

    /// Runs a command with the User Account Control prompt (Windows); only
    /// its exit code is available, not its output.
    fn run_elevated(&self, argv: &[String], timeout: Duration) -> RunResult {
        self.run(argv, timeout)
    }
}

/// Runs commands with `std::process`, no shell, a closed standard input,
/// and a kill at the timeout.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> RunResult {
        let Some((prog, args)) = argv.split_first() else {
            return RunResult {
                spawn_error: Some("empty command".into()),
                ..Default::default()
            };
        };
        debug_assert!(Path::new(prog).is_absolute());
        let child = no_console(&mut Command::new(prog))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                return RunResult {
                    spawn_error: Some(format!("{prog}: {e}")),
                    ..Default::default()
                }
            }
        };
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_t = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.take(64 * 1024).read_to_string(&mut s);
            }
            s
        });
        let err_t = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(p) = err_pipe.as_mut() {
                let _ = p.take(64 * 1024).read_to_string(&mut s);
            }
            s
        });
        let start = Instant::now();
        let (code, timed_out) = loop {
            match child.try_wait() {
                Ok(Some(st)) => break (st.code(), false),
                Ok(None) if start.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => {
                    return RunResult {
                        spawn_error: Some(e.to_string()),
                        ..Default::default()
                    }
                }
            }
        };
        RunResult {
            code,
            stdout: out_t.join().unwrap_or_default(),
            stderr: err_t.join().unwrap_or_default(),
            timed_out,
            spawn_error: None,
        }
    }

    #[cfg(windows)]
    fn run_elevated(&self, argv: &[String], timeout: Duration) -> RunResult {
        crate::winproc::run_elevated(argv, timeout)
    }
}

/// The customer-code bit of an `smcpctl service` exit code that carries a
/// Win32 error code (cmd/smcpctl/servicecmd.go).
pub const WIN32_EXIT_BIT: i32 = 0x2000_0000;

/// The text for an exit code of `smcpctl service` that carries a Win32
/// error code, with `message` giving the system's text (Windows).
pub fn win32_exit_detail(code: Option<i32>, message: impl Fn(u32) -> Option<String>) -> Option<String> {
    let c = code?;
    if c <= 0 || c & WIN32_EXIT_BIT == 0 {
        return None;
    }
    let errno = (c & 0xFFFF) as u32;
    Some(match message(errno) {
        Some(m) => format!("{m} (error {errno})"),
        None => format!("Windows error {errno}"),
    })
}

fn system_message(_code: u32) -> Option<String> {
    #[cfg(windows)]
    {
        crate::winproc::win32_message(_code)
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Queries the service's status.
pub fn status(r: &dyn Runner, m: Option<&Manager>) -> ServiceStatus {
    match m {
        None => ServiceStatus::NotInstalled,
        Some(m) => parse_status(m, &r.run(&status_argv(m), STATUS_TIMEOUT)),
    }
}

/// Performs an action and returns the message to report: success, or the
/// service manager's error text (FR-20.3).
pub fn perform(r: &dyn Runner, m: Option<&Manager>, a: Action) -> Result<String, String> {
    let Some(m) = m else {
        return Err("No Gateway service is installed. Run the first-run setup or `smcpctl install` first.".into());
    };
    let argv = action_argv(m, a);
    let res = if needs_uac(m) {
        r.run_elevated(&argv, ACTION_TIMEOUT)
    } else {
        r.run(&argv, ACTION_TIMEOUT)
    };
    if res.timed_out {
        return Err(format!(
            "`{}` did not finish within {} seconds.",
            argv.join(" "),
            ACTION_TIMEOUT.as_secs()
        ));
    }
    if let Some(e) = res.spawn_error {
        return Err(format!("Could not run the service manager: {e}"));
    }
    if res.code == Some(0) {
        return Ok(format!(
            "The Gateway service was {}.",
            match a {
                Action::Start => "started",
                Action::Stop => "stopped",
                Action::Restart => "restarted",
            }
        ));
    }
    let win32 = win32_exit_detail(res.code, system_message);
    let detail = if let Some(w) = win32.as_deref() {
        w
    } else if res.stderr.trim().is_empty() {
        res.stdout.trim()
    } else {
        res.stderr.trim()
    };
    let code = match res.code {
        Some(c) if c > 0 && c & WIN32_EXIT_BIT != 0 => format!("{c:#x}"),
        Some(c) => c.to_string(),
        None => "a signal".into(),
    };
    Err(format!(
        "Could not {} the Gateway service (`{}` exited with {code}): {detail}",
        a.verb(),
        argv.join(" ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use std::sync::Mutex;

    struct Fake {
        calls: Mutex<Vec<(Vec<String>, Duration)>>,
        elevated: Mutex<Vec<Vec<String>>>,
        result: RunResult,
    }

    impl Runner for Fake {
        fn run(&self, argv: &[String], timeout: Duration) -> RunResult {
            self.calls.lock().unwrap().push((argv.to_vec(), timeout));
            self.result.clone()
        }

        fn run_elevated(&self, argv: &[String], timeout: Duration) -> RunResult {
            self.elevated.lock().unwrap().push(argv.to_vec());
            self.run(argv, timeout)
        }
    }

    fn fake(result: RunResult) -> Fake {
        Fake {
            calls: Mutex::new(Vec::new()),
            elevated: Mutex::new(Vec::new()),
            result,
        }
    }

    fn windows_host(d: &Path) -> Host {
        Host {
            os: "windows",
            home: d.join("Users/u"),
            xdg_config_home: None,
            etc_systemd: d.join("none"),
            uid: 0,
            win: WinDirs {
                local_app_data: Some(d.join("Users/u/AppData/Local")),
                program_data: Some(d.join("ProgramData")),
                program_files: Some(d.join("Program Files")),
                exe_dir: Some(d.join("Program Files/Secure MCP Gateway")),
            },
        }
    }

    #[test]
    fn windows_detects_the_per_user_and_the_machine_installation() {
        claims::partial(&["FR-20.3", "FR-20.1"]);
        let d = tempdir::Dir::new();
        let h = windows_host(d.path());
        assert_eq!(detect(&h), None);
        let app_smcpctl = d.path().join("Program Files/Secure MCP Gateway/smcpctl.exe");
        touch(&app_smcpctl);
        // The machine mode: its definition file and the administrators'
        // smcpctl in %ProgramFiles%\smcp-gateway.
        let machine_cfg = d.path().join("ProgramData/smcp-gateway/config");
        touch(&machine_cfg.join("smcpd-service.txt"));
        assert_eq!(detect(&h), None, "machine mode without the administrators' smcpctl");
        let machine_smcpctl = d.path().join("Program Files/smcp-gateway/smcpctl.exe");
        touch(&machine_smcpctl);
        assert_eq!(
            detect(&h),
            Some(Manager::WindowsMachine {
                smcpctl: machine_smcpctl.clone(),
                config: machine_cfg.join("smcp.toml"),
            })
        );
        // A per-user installation (Task Scheduler task or Run value) wins,
        // controlled with the application's own smcpctl.
        let user_cfg = d.path().join("Users/u/AppData/Local/smcp-gateway/config");
        for f in ["smcpd-run.txt", "smcpd-task.xml"] {
            touch(&user_cfg.join(f));
            assert_eq!(
                detect(&h),
                Some(Manager::WindowsUser {
                    smcpctl: app_smcpctl.clone(),
                    config: user_cfg.join("smcp.toml"),
                })
            );
            std::fs::remove_file(user_cfg.join(f)).unwrap();
        }
    }

    #[test]
    fn windows_controls_go_through_smcpctl_and_elevate_only_the_machine_service() {
        claims::partial(&["FR-20.3", "SR-2-7", "FR-20.1"]);
        let user = Manager::WindowsUser {
            smcpctl: PathBuf::from(r"C:\Program Files\Secure MCP Gateway\smcpctl.exe"),
            config: PathBuf::from(r"C:\Users\u\AppData\Local\smcp-gateway\config\smcp.toml"),
        };
        let machine = Manager::WindowsMachine {
            smcpctl: PathBuf::from(r"C:\Program Files\smcp-gateway\smcpctl.exe"),
            config: PathBuf::from(r"C:\ProgramData\smcp-gateway\config\smcp.toml"),
        };
        assert_eq!(
            action_argv(&user, Action::Restart),
            v(&[
                r"C:\Program Files\Secure MCP Gateway\smcpctl.exe",
                "service",
                "restart",
                "--config",
                r"C:\Users\u\AppData\Local\smcp-gateway\config\smcp.toml"
            ])
        );
        assert_eq!(
            status_argv(&machine),
            v(&[
                r"C:\Program Files\smcp-gateway\smcpctl.exe",
                "service",
                "status",
                "--config",
                r"C:\ProgramData\smcp-gateway\config\smcp.toml"
            ])
        );
        assert!(!needs_uac(&user) && needs_uac(&machine));
        assert!(!needs_uac(&Manager::SystemdSystem), "pkexec is in the argument vector");
        for a in [Action::Start, Action::Stop, Action::Restart] {
            let ok = fake(RunResult {
                code: Some(0),
                ..Default::default()
            });
            assert!(perform(&ok, Some(&user), a).is_ok());
            assert!(
                ok.elevated.lock().unwrap().is_empty(),
                "the per-user mode ran a command with User Account Control"
            );
            assert!(perform(&ok, Some(&machine), a).is_ok());
            assert_eq!(*ok.elevated.lock().unwrap(), vec![action_argv(&machine, a)]);
        }
        // The status query is never elevated.
        let st = fake(RunResult {
            code: Some(0),
            stdout: "running\r\n".into(),
            ..Default::default()
        });
        assert_eq!(status(&st, Some(&machine)), ServiceStatus::Running);
        assert!(st.elevated.lock().unwrap().is_empty());
        let r = |code, out: &str| RunResult {
            code: Some(code),
            stdout: out.into(),
            ..Default::default()
        };
        assert_eq!(parse_status(&user, &r(0, "stopped\n")), ServiceStatus::Stopped);
        assert_eq!(
            parse_status(&user, &r(0, "not-installed\n")),
            ServiceStatus::NotInstalled
        );
        assert_eq!(parse_status(&user, &r(1, "running\n")), ServiceStatus::Unknown);
        assert_eq!(parse_status(&user, &r(0, "something else")), ServiceStatus::Unknown);
    }

    #[test]
    fn windows_failures_carry_the_service_managers_text() {
        claims::partial(&["FR-20.3"]);
        let machine = Manager::WindowsMachine {
            smcpctl: PathBuf::from(r"C:\Program Files\smcp-gateway\smcpctl.exe"),
            config: PathBuf::from(r"C:\ProgramData\smcp-gateway\config\smcp.toml"),
        };
        // smcpctl ends with the customer bit and ERROR_SERVICE_DISABLED.
        let disabled = fake(RunResult {
            code: Some(0x2000_0000 | 1058),
            ..Default::default()
        });
        let err = perform(&disabled, Some(&machine), Action::Start).unwrap_err();
        assert!(err.contains("Could not start the Gateway service"), "{err}");
        assert!(err.contains("1058"), "{err}");
        assert!(err.contains("0x20000422"), "{err}");
        assert_eq!(
            win32_exit_detail(Some(0x2000_0000 | 5), |c| (c == 5).then(|| "Access is denied.".into())),
            Some("Access is denied. (error 5)".into())
        );
        assert_eq!(win32_exit_detail(Some(1), |_| None), None);
        assert_eq!(win32_exit_detail(Some(-1), |_| None), None);
        assert_eq!(win32_exit_detail(None, |_| None), None);
        // A declined consent prompt.
        let declined = fake(RunResult {
            spawn_error: Some("the User Account Control prompt was declined".into()),
            ..Default::default()
        });
        assert!(perform(&declined, Some(&machine), Action::Stop)
            .unwrap_err()
            .contains("declined"));
    }

    #[test]
    fn windows_command_lines_follow_the_c_runtime_rules() {
        claims::partial(&["SR-2-7"]);
        let q = |a: &[&str]| windows_command_line(&v(a));
        assert_eq!(q(&["service", "start"]), "service start");
        assert_eq!(
            q(&["--config", r"C:\ProgramData\smcp-gateway\config\smcp.toml"]),
            r"--config C:\ProgramData\smcp-gateway\config\smcp.toml"
        );
        assert_eq!(q(&[r"C:\Program Files\x"]), r#""C:\Program Files\x""#);
        assert_eq!(q(&[""]), r#""""#);
        assert_eq!(q(&[r#"a"b"#]), r#""a\"b""#);
        assert_eq!(q(&[r"a b\"]), r#""a b\\""#);
        assert_eq!(q(&[r#"a\"b c"#]), r#""a\\\"b c""#);
        assert_eq!(q(&["a&b|c%PATH%"]), "a&b|c%PATH%");
    }

    fn host(os: &'static str) -> (tempdir::Dir, Host) {
        let d = tempdir::Dir::new();
        let h = Host {
            os,
            home: d.path().join("home"),
            xdg_config_home: None,
            etc_systemd: d.path().join("etc/systemd/system"),
            uid: 501,
            win: WinDirs::default(),
        };
        (d, h)
    }

    mod tempdir {
        use std::path::{Path, PathBuf};
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                let p = std::env::temp_dir().join(format!(
                    "smcp-desktop-test-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, "").unwrap();
    }

    #[test]
    fn detects_the_unit_smcpctl_installed() {
        claims::partial(&["FR-20.3"]);
        let (_d, h) = host("macos");
        assert_eq!(detect(&h), None);
        let plist = h.home.join("Library/LaunchAgents/com.smcp.gateway.plist");
        touch(&plist);
        assert_eq!(detect(&h), Some(Manager::Launchd { uid: 501, plist }));

        let (_d, h) = host("linux");
        assert_eq!(detect(&h), None);
        touch(&h.etc_systemd.join("smcpd.service"));
        assert_eq!(detect(&h), Some(Manager::SystemdSystem));
        touch(&h.home.join(".config/systemd/user/smcpd.service"));
        assert_eq!(detect(&h), Some(Manager::SystemdUser));
        assert_eq!(detect(&Host { os: "windows", ..h }), None);
    }

    #[test]
    fn fixed_argument_vectors_through_the_service_manager() {
        claims::partial(&["FR-20.3", "SR-2-7"]);
        let l = Manager::Launchd {
            uid: 501,
            plist: PathBuf::from("/Users/u/Library/LaunchAgents/com.smcp.gateway.plist"),
        };
        assert_eq!(
            action_argv(&l, Action::Start),
            v(&[
                "/bin/launchctl",
                "bootstrap",
                "gui/501",
                "/Users/u/Library/LaunchAgents/com.smcp.gateway.plist"
            ])
        );
        assert_eq!(
            action_argv(&l, Action::Stop),
            v(&["/bin/launchctl", "bootout", "gui/501/com.smcp.gateway"])
        );
        assert_eq!(
            action_argv(&l, Action::Restart),
            v(&["/bin/launchctl", "kickstart", "-k", "gui/501/com.smcp.gateway"])
        );
        assert_eq!(
            status_argv(&l),
            v(&["/bin/launchctl", "print", "gui/501/com.smcp.gateway"])
        );
        for a in [Action::Start, Action::Stop, Action::Restart] {
            assert_eq!(
                action_argv(&Manager::SystemdUser, a),
                v(&["/usr/bin/systemctl", "--user", a.verb(), "smcpd.service"])
            );
            // Elevation only for the system unit, with the command named.
            let sys = action_argv(&Manager::SystemdSystem, a);
            assert_eq!(&sys[..2], &v(&["/usr/bin/pkexec", "/usr/bin/systemctl"])[..]);
            assert!(!action_argv(&l, a)
                .iter()
                .any(|s| s.contains("pkexec") || s.contains("sudo")));
            assert!(!action_argv(&Manager::SystemdUser, a)
                .iter()
                .any(|s| s.contains("pkexec") || s.contains("sudo")));
        }
        assert_eq!(
            action_argv(&Manager::SystemdSystem, Action::Start),
            v(&[
                "/usr/bin/pkexec",
                "/usr/bin/systemctl",
                "start",
                "smcp-nftables.service",
                "smcpd.service"
            ])
        );
        assert_eq!(
            status_argv(&Manager::SystemdSystem),
            v(&["/usr/bin/systemctl", "is-active", "smcpd.service"])
        );
        // Unix paths are absolute only on Unix.
        if cfg!(unix) {
            for m in [&l, &Manager::SystemdUser, &Manager::SystemdSystem] {
                for a in [Action::Start, Action::Stop, Action::Restart] {
                    assert!(Path::new(&action_argv(m, a)[0]).is_absolute());
                }
            }
        }
    }

    #[test]
    fn reports_outcome_and_error_text_within_30_seconds() {
        claims::partial(&["FR-20.3"]);
        let m = Manager::SystemdUser;
        let ok = fake(RunResult {
            code: Some(0),
            ..Default::default()
        });
        assert_eq!(
            perform(&ok, Some(&m), Action::Restart),
            Ok("The Gateway service was restarted.".into())
        );
        assert_eq!(ok.calls.lock().unwrap()[0].1, Duration::from_secs(30));

        let failing = fake(RunResult {
            code: Some(5),
            stderr: "Failed to start smcpd.service: Unit smcpd.service has a bad unit file setting.\n".into(),
            ..Default::default()
        });
        let err = perform(&failing, Some(&m), Action::Start).unwrap_err();
        assert!(err.contains("Unit smcpd.service has a bad unit file setting."), "{err}");
        assert!(err.contains("exited with 5"), "{err}");

        let slow = fake(RunResult {
            timed_out: true,
            ..Default::default()
        });
        assert!(perform(&slow, Some(&m), Action::Stop)
            .unwrap_err()
            .contains("within 30 seconds"));
        assert!(perform(&ok, None, Action::Start)
            .unwrap_err()
            .contains("No Gateway service is installed"));
    }

    #[test]
    fn status_from_the_service_manager() {
        claims::partial(&["FR-20.3", "FR-20.2"]);
        let l = Manager::Launchd {
            uid: 501,
            plist: PathBuf::from("/p"),
        };
        let r = |code, out: &str| RunResult {
            code: Some(code),
            stdout: out.into(),
            ..Default::default()
        };
        assert_eq!(parse_status(&l, &r(0, "state = running")), ServiceStatus::Running);
        assert_eq!(parse_status(&l, &r(113, "")), ServiceStatus::Stopped);
        assert_eq!(
            parse_status(&Manager::SystemdUser, &r(0, "active\n")),
            ServiceStatus::Running
        );
        assert_eq!(
            parse_status(&Manager::SystemdUser, &r(3, "inactive\n")),
            ServiceStatus::Stopped
        );
        assert_eq!(
            parse_status(&Manager::SystemdSystem, &r(3, "failed\n")),
            ServiceStatus::Stopped
        );
        assert_eq!(parse_status(&Manager::SystemdUser, &r(4, "")), ServiceStatus::Unknown);
        assert_eq!(
            parse_status(
                &l,
                &RunResult {
                    timed_out: true,
                    ..Default::default()
                }
            ),
            ServiceStatus::Unknown
        );
        assert_eq!(status(&fake(RunResult::default()), None), ServiceStatus::NotInstalled);
    }

    #[cfg(unix)]
    #[test]
    fn the_system_runner_runs_without_a_shell_and_times_out() {
        claims::partial(&["FR-20.3"]);
        let r = SystemRunner.run(
            &v(&["/bin/sh", "-c", "echo out; echo err >&2; exit 3"]),
            Duration::from_secs(5),
        );
        assert_eq!(
            (r.code, r.stdout.as_str(), r.stderr.as_str(), r.timed_out),
            (Some(3), "out\n", "err\n", false)
        );
        let start = Instant::now();
        let r = SystemRunner.run(&v(&["/bin/sleep", "10"]), Duration::from_millis(300));
        assert!(r.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(SystemRunner
            .run(&v(&["/nonexistent/program"]), Duration::from_secs(1))
            .spawn_error
            .is_some());
    }
}
