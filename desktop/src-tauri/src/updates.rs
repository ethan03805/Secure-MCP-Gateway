//! The Check for Updates window's state and operations (SRS FR-20.11 to
//! FR-20.13, SR-7-2), without Tauri: a check of the release feed, the
//! desktop application update through its platform installer, and the
//! Gateway upgrade through `smcpctl upgrade`. `lib.rs` runs each operation
//! on a background thread and the window reads `View` every second.
//!
//! Error messages are catalogue codes (`docs/design/messages.json`,
//! FR-20.47, FR-20.48) with their parameters and the underlying output for
//! the details area; the window takes the text from the catalogue.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use semver::Version;
use serde::Serialize;
use url::Url;

use crate::installer::{self, Kind};
use crate::release::{self, FeedError, Found, Http, Release};
use crate::upgrade::{self, Installation, NotHere, Outcome};
use crate::verify::{self, Check, Cosign, VerifyError};

/// The Linux package managers get this long before the update is reported
/// as failed.
#[cfg(target_os = "linux")]
const PACKAGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
const LOG_LINES: usize = 400;

/// A message for the window: a catalogue code, its parameters, and the
/// underlying output for the details area (FR-20.47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Message {
    pub code: &'static str,
    pub params: BTreeMap<&'static str, String>,
    pub details: String,
}

fn message(code: &'static str, params: &[(&'static str, String)], details: impl Into<String>) -> Message {
    Message {
        code,
        params: params.iter().cloned().collect(),
        details: details.into(),
    }
}

/// What the window shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    /// idle, checking, latest, available, working, installer-started,
    /// upgraded, failed.
    pub phase: &'static str,
    /// The application's version.
    pub installed: String,
    /// The newest stable release found by the last successful check.
    pub latest: Option<String>,
    /// The newest release is newer than the application.
    pub app_newer: bool,
    /// A newer release exists and its notes can be opened.
    pub notes: bool,
    /// How the application was installed, when it can update itself.
    pub app_kind: Option<String>,
    /// Why the application cannot update itself, when it cannot.
    pub app_blocked: Option<String>,
    /// The Gateway's installed version, when known.
    pub gateway: Option<String>,
    /// The Gateway can be upgraded from the window.
    pub gateway_upgradable: bool,
    /// Why not, and the terminal command to use instead.
    pub gateway_blocked: Option<String>,
    /// Progress lines of the running operation.
    pub log: Vec<String>,
    pub message: Option<Message>,
}

/// What the operations need from the host; tests supply their own.
pub struct Env {
    pub http: Arc<dyn Http>,
    pub feed: Url,
    pub pubkey: String,
    /// Finds cosign at the time of each verification.
    pub cosign: Arc<dyn Fn() -> Option<Arc<dyn Cosign>> + Send + Sync>,
    pub app_version: Version,
    pub os: String,
    pub arch: String,
    pub kind: Option<Kind>,
    /// Where releases are downloaded (the application's cache directory).
    pub download_root: PathBuf,
    /// Where the time of the last check is kept.
    pub config_dir: PathBuf,
    /// Finds the Standalone Gateway installation.
    pub installation: Arc<dyn Fn() -> Result<Installation, NotHere> + Send + Sync>,
    /// Starts the installer; returns the output and whether it succeeded.
    /// Starts the installer for the verified files and their digests;
    /// returns its output, or the error and output.
    #[allow(clippy::type_complexity)]
    pub start: Arc<dyn Fn(&Kind, &[PathBuf], &[String], &mut dyn FnMut(&str)) -> Result<String, String> + Send + Sync>,
}

pub struct Updates {
    env: Env,
    view: Mutex<View>,
    release: Mutex<Option<Release>>,
    busy: Mutex<bool>,
}

impl Updates {
    pub fn new(mut env: Env) -> Updates {
        // A build without a release version (0.x, as built from source)
        // cannot tell newer from older, so it never updates itself: the
        // version rule of SR-7-2 needs the true installed version.
        let unversioned = env.app_version.major == 0;
        if unversioned {
            env.kind = None;
        }
        let (app_kind, app_blocked) = match &env.kind {
            Some(k) => (Some(k.label().to_string()), None),
            None if unversioned => (
                None,
                Some(format!(
                    "This build of the app has no release version ({}), so it is not updated from here.",
                    env.app_version
                )),
            ),
            None => (
                None,
                Some(
                    "This copy of the app was not installed from a release installer, so it is not updated from here."
                        .to_string(),
                ),
            ),
        };
        let view = View {
            phase: "idle",
            installed: env.app_version.to_string(),
            latest: None,
            app_newer: false,
            notes: false,
            app_kind,
            app_blocked,
            gateway: None,
            gateway_upgradable: false,
            gateway_blocked: None,
            log: Vec::new(),
            message: None,
        };
        Updates {
            env,
            view: Mutex::new(view),
            release: Mutex::new(None),
            busy: Mutex::new(false),
        }
    }

    pub fn view(&self) -> View {
        self.view.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The release notes page of the newer release, if one was found.
    pub fn notes_url(&self) -> Option<Url> {
        let v = self.view();
        if !v.notes {
            return None;
        }
        self.release
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|r| r.notes_url.clone())
    }

    fn set(&self, f: impl FnOnce(&mut View)) {
        f(&mut self.view.lock().unwrap_or_else(|e| e.into_inner()));
    }

    fn log(&self, line: &str) {
        self.set(|v| {
            v.log.push(line.to_string());
            if v.log.len() > LOG_LINES {
                let n = v.log.len() - LOG_LINES;
                v.log.drain(..n);
            }
        });
    }

    /// Runs `f` unless another operation runs; returns false if one does.
    fn exclusive(&self, f: impl FnOnce()) -> bool {
        {
            let mut b = self.busy.lock().unwrap_or_else(|e| e.into_inner());
            if *b {
                return false;
            }
            *b = true;
        }
        f();
        *self.busy.lock().unwrap_or_else(|e| e.into_inner()) = false;
        true
    }

    /// Whether an automatic check is due now (FR-20.11).
    pub fn auto_due(&self, enabled: bool, now: SystemTime) -> bool {
        release::auto_due(enabled, release::load_last_check(&self.env.config_dir), now)
    }

    /// Checks the feed. A manual check reports a failure with
    /// `UPDATE_CHECK_FAILED`; an automatic one keeps the window as it was,
    /// so an offline host sees no error it did not ask for. Returns the
    /// newer version when one was found.
    pub fn check(&self, manual: bool, now: SystemTime) -> Option<Version> {
        let mut newer = None;
        self.exclusive(|| newer = self.check_inner(manual, now));
        newer
    }

    fn check_inner(&self, manual: bool, now: SystemTime) -> Option<Version> {
        if manual {
            self.set(|v| {
                v.phase = "checking";
                v.message = None;
                v.log.clear();
            });
        }
        // The attempt counts, successful or not (no retry loop offline).
        let _ = release::save_last_check(&self.env.config_dir, now);
        self.refresh_gateway();
        let fetched = release::latest(self.env.http.as_ref(), &self.env.feed);
        let gateway = self.view().gateway.and_then(|g| Version::parse(&g).ok());
        match fetched {
            Ok(r) => {
                let latest = r.as_ref().map(|r| r.version.clone());
                let app_newer = matches!(release::compare(r.clone(), &self.env.app_version), Found::Newer(_));
                let gateway_newer = match (&latest, &gateway) {
                    (Some(l), Some(g)) => l > g,
                    _ => false,
                };
                *self.release.lock().unwrap_or_else(|e| e.into_inner()) = r;
                self.set(|v| {
                    v.phase = if app_newer || gateway_newer {
                        "available"
                    } else {
                        "latest"
                    };
                    v.latest = latest.as_ref().map(Version::to_string);
                    v.app_newer = app_newer;
                    v.notes = app_newer || gateway_newer;
                    v.message = None;
                });
                if app_newer {
                    latest
                } else {
                    None
                }
            }
            Err(e) => {
                if manual {
                    let detail = match &e {
                        FeedError::Network(m) | FeedError::Invalid(m) => m.clone(),
                    };
                    self.set(|v| {
                        v.phase = "failed";
                        v.message = Some(message(
                            "UPDATE_CHECK_FAILED",
                            &[],
                            format!("{}\n{}", self.env.feed, detail),
                        ));
                    });
                } else {
                    eprintln!("smcp-desktop: automatic update check failed: {e}");
                }
                None
            }
        }
    }

    /// Reads the Gateway's installed version and whether the window can
    /// upgrade it.
    fn refresh_gateway(&self) {
        let (version, upgradable, blocked) = match (self.env.installation)() {
            Ok(inst) => (upgrade::installed_version(&inst.smcpctl()), true, None),
            Err(NotHere::NotInstalled) => (None, false, Some("No Gateway service is set up on this computer.".to_string())),
            Err(NotHere::Enforced) => (
                None,
                false,
                Some("The Enforced installation is upgraded as root in a terminal with sudo smcpctl upgrade, as docs/install.md describes under Upgrade and rollback.".to_string()),
            ),
            Err(NotHere::Packaged(f)) => (
                None,
                false,
                Some(format!("The Gateway was installed by the {f} package and is updated with it: update the app, which installs both.")),
            ),
            Err(NotHere::Unreadable(m)) => (None, false, Some(format!("The Gateway service definition could not be read: {m}"))),
            Err(NotHere::Windows) => (
                None,
                false,
                Some("On Windows the Gateway is upgraded with smcpctl upgrade in a terminal, or with the smcp-desktop .msi, which Update App installs.".to_string()),
            ),
        };
        self.set(|v| {
            v.gateway = version.map(|x| x.to_string());
            v.gateway_upgradable = upgradable;
            v.gateway_blocked = blocked;
        });
    }

    fn fail_verify(&self, e: &VerifyError, installed: &Version, offered: &Version) {
        let m = if e.check == Check::Version {
            message(
                "UPDATE_NOT_NEWER",
                &[("offered", offered.to_string()), ("installed", installed.to_string())],
                e.detail.clone(),
            )
        } else {
            message(
                "UPDATE_VERIFY_FAILED",
                &[("check", e.check.name().to_string())],
                e.detail.clone(),
            )
        };
        self.set(|v| {
            v.phase = "failed";
            v.message = Some(m);
        });
    }

    fn current_release(&self) -> Option<Release> {
        self.release.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn fresh_dir(&self, what: &str, v: &Version) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        self.env.download_root.join(format!("{what}-{v}-{stamp}"))
    }

    fn cosign(&self) -> Option<Arc<dyn Cosign>> {
        (self.env.cosign)()
    }

    /// FR-20.13: downloads the release's installer of the kind that
    /// installed the application, verifies it (SR-7-2) and starts it.
    /// Returns the kind when the installer was started.
    pub fn update_app(&self) -> Option<Kind> {
        let mut out = None;
        self.exclusive(|| out = self.update_app_inner());
        out
    }

    fn update_app_inner(&self) -> Option<Kind> {
        let rel = self.current_release()?;
        let kind = self.env.kind.clone()?;
        self.set(|v| {
            v.phase = "working";
            v.message = None;
            v.log.clear();
        });
        let installed = self.env.app_version.clone();
        let wanted = match installer::files_for(&kind, &rel.version, &self.env.arch, &rel.assets) {
            Ok(w) => w,
            Err(e) => {
                self.fail_verify(
                    &VerifyError {
                        check: Check::Files,
                        detail: e,
                    },
                    &installed,
                    &rel.version,
                );
                return None;
            }
        };
        self.log(&format!("Downloading {} from release {}.", wanted.join(", "), rel.tag));
        let cosign = self.cosign();
        if cosign.is_none() {
            self.log("cosign is not installed; the Sigstore bundle is not checked. The minisign signature and the SHA-256 checksums are.");
        }
        let dir = self.fresh_dir("app", &rel.version);
        let verified = match verify::fetch_verified(
            self.env.http.as_ref(),
            &rel,
            &wanted,
            &installed,
            &self.env.pubkey,
            cosign.as_deref(),
            &dir,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.fail_verify(&e, &installed, &rel.version);
                return None;
            }
        };
        self.log(&format!(
            "Verified: the minisign signature of {} with the release key{}, and the SHA-256 checksum of each file.",
            verify::checksum_file_name(&rel.version),
            if verified.sigstore_checked {
                ", its Sigstore bundle with cosign"
            } else {
                ""
            }
        ));
        let mut log = |l: &str| self.log(l);
        let started = (self.env.start)(&kind, &verified.files, &verified.digests, &mut log);
        match started {
            Ok(out) => {
                if !out.is_empty() {
                    self.log(&out);
                }
                self.set(|v| v.phase = "installer-started");
                Some(kind)
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&verified.dir);
                self.set(|v| {
                    v.phase = "failed";
                    v.message = Some(message(
                        "UPDATE_INSTALL_FAILED",
                        &[("kind", kind.label().to_string())],
                        e,
                    ));
                });
                None
            }
        }
    }

    /// FR-20.12: downloads the Gateway release archive, verifies it
    /// (SR-7-2) and runs `smcpctl upgrade` with the backup passphrase on
    /// its standard input.
    pub fn upgrade_gateway(&self, passphrase: &str) -> Option<Outcome> {
        let mut out = None;
        self.exclusive(|| out = self.upgrade_gateway_inner(passphrase));
        out
    }

    fn upgrade_gateway_inner(&self, passphrase: &str) -> Option<Outcome> {
        let rel = self.current_release()?;
        let inst = match (self.env.installation)() {
            Ok(i) => i,
            Err(_) => {
                self.refresh_gateway();
                return None;
            }
        };
        self.set(|v| {
            v.phase = "working";
            v.message = None;
            v.log.clear();
        });
        let before = upgrade::installed_version(&inst.smcpctl());
        let Some(before_v) = before.clone() else {
            self.set(|v| {
                v.phase = "failed";
                v.message = Some(message(
                    "UPGRADE_FAILED",
                    &[("version", "unknown".into())],
                    format!("{} version --short did not report a version", inst.smcpctl().display()),
                ));
            });
            return None;
        };
        let Some(archive) = upgrade::archive_name(&rel.version, &self.env.os, &self.env.arch) else {
            self.fail_verify(
                &VerifyError {
                    check: Check::Files,
                    detail: format!("no Gateway archive for {} {}", self.env.os, self.env.arch),
                },
                &before_v,
                &rel.version,
            );
            return None;
        };
        self.log(&format!("Downloading {archive} from release {}.", rel.tag));
        let dir = self.fresh_dir("gateway", &rel.version);
        let cosign = self.cosign();
        let verified = match verify::fetch_verified(
            self.env.http.as_ref(),
            &rel,
            &[archive],
            &before_v,
            &self.env.pubkey,
            cosign.as_deref(),
            &dir,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.fail_verify(&e, &before_v, &rel.version);
                return None;
            }
        };
        self.log("Verified. Running smcpctl upgrade.");
        let argv = upgrade::upgrade_argv(&inst, &verified.dir);
        let ran = upgrade::run_fixed(&argv, Some(passphrase), upgrade::UPGRADE_TIMEOUT, &mut |l| self.log(l));
        let _ = std::fs::remove_dir_all(&verified.dir);
        let after = upgrade::installed_version(&inst.smcpctl());
        let outcome = upgrade::classify(&ran, before.as_ref(), after.as_ref());
        let details = format!("{}\n\n{}", argv.join(" "), ran.summary());
        self.set(|v| {
            v.gateway = after.as_ref().map(Version::to_string);
            match &outcome {
                Outcome::Upgraded { .. } => {
                    v.phase = "upgraded";
                    v.message = None;
                }
                Outcome::RolledBack { running } => {
                    v.phase = "failed";
                    v.message = Some(message(
                        "UPGRADE_ROLLED_BACK",
                        &[("version", running.clone())],
                        details.clone(),
                    ));
                }
                Outcome::Failed { running } => {
                    v.phase = "failed";
                    v.message = Some(message(
                        "UPGRADE_FAILED",
                        &[("version", running.clone())],
                        details.clone(),
                    ));
                }
            }
        });
        Some(outcome)
    }
}

/// Starts the installer for verified files (the production `Env::start`).
/// On Linux the packages go to the package manager as sealed copies whose
/// digests must equal the verified ones.
pub fn start_installer(
    kind: &Kind,
    files: &[PathBuf],
    digests: &[String],
    log: &mut dyn FnMut(&str),
) -> Result<String, String> {
    match kind {
        Kind::AppImage(target) => {
            let f = files.first().ok_or("no AppImage downloaded")?;
            installer::replace_appimage(f, target).map_err(|e| format!("{}: {e}", target.display()))?;
            Ok(format!("Replaced {}.", target.display()))
        }
        #[cfg(target_os = "linux")]
        Kind::Deb | Kind::Rpm => {
            let mut sealed = Vec::new();
            for (f, want) in files.iter().zip(digests) {
                let name = f
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let s = installer::sealed::Sealed::from_file(f, &name).map_err(|e| format!("{name}: {e}"))?;
                if s.sha256 != *want {
                    return Err(format!(
                        "{name} changed after it was verified (expected {want}, got {})",
                        s.sha256
                    ));
                }
                sealed.push(s);
            }
            let paths: Vec<PathBuf> = sealed.iter().map(|s| s.path()).collect();
            let argv = installer::start_argv(kind, &paths).ok_or("no installer command")?;
            log(&format!("Running {}", argv.join(" ")));
            let r = upgrade::run_fixed(&argv, None, PACKAGE_TIMEOUT, log);
            drop(sealed);
            if r.code == Some(0) {
                Ok(String::new())
            } else {
                Err(format!("{}\n{}", argv.join(" "), r.summary()))
            }
        }
        _ => {
            // macOS and Windows: re-check each file just before it is opened.
            for (f, want) in files.iter().zip(digests) {
                let got = verify::sha256_file(f).map_err(|e| format!("{}: {e}", f.display()))?;
                if got != *want {
                    return Err(format!("{} changed after it was verified", f.display()));
                }
            }
            let argv = installer::start_argv(kind, files).ok_or("no installer command")?;
            log(&format!("Running {}", argv.join(" ")));
            spawn_detached(&argv)
        }
    }
}

/// Starts a program and does not wait for it (an installer that outlives
/// the application).
fn spawn_detached(argv: &[String]) -> Result<String, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    if !Path::new(prog).is_absolute() {
        return Err(format!("{prog} is not an absolute path"));
    }
    std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| String::new())
        .map_err(|e| format!("{prog}: {e}"))
}

/// Removes download directories left by earlier runs (an installer that
/// was started reads its file before the application starts again).
pub fn clean_downloads(root: &Path) {
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;
    use crate::release::testfeed::Server;
    use crate::release::NetHttp;
    use crate::verify::testkey::Key;
    use std::time::Duration;

    type Started = Arc<Mutex<Vec<(Kind, Vec<PathBuf>)>>>;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "smcp-desktop-updates-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct Fixture {
        srv: Server,
        key: Key,
        dir: PathBuf,
        started: Started,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            Fixture {
                srv: Server::start(),
                key: Key::new(),
                dir: tmp(tag),
                started: Arc::default(),
            }
        }

        /// Publishes `v` with a macOS package and a darwin archive.
        fn publish(&self, v: &str) {
            let pkg = format!("smcp_{v}_darwin_arm64.pkg");
            let tgz = format!("smcp_{v}_darwin_arm64.tar.gz");
            let sums_name = format!("smcp_{v}_checksums.txt");
            let pkg_body = format!("pkg {v}");
            let tgz_body = format!("tgz {v}");
            let sums = format!(
                "{}  {pkg}\n{}  {tgz}\n",
                verify::sha256(pkg_body.as_bytes()),
                verify::sha256(tgz_body.as_bytes())
            );
            let sig = self.key.sign(sums.as_bytes(), &format!("smcp {v} file:{sums_name}"));
            let files = [
                (sums_name.clone(), sums.into_bytes()),
                (format!("{sums_name}.minisig"), sig.into_bytes()),
                (pkg, pkg_body.into_bytes()),
                (tgz, tgz_body.into_bytes()),
            ];
            for (n, b) in &files {
                self.srv.put(&format!("/dl/{n}"), b.clone());
            }
            let doc = serde_json::json!({
                "tag_name": format!("v{v}"),
                "html_url": self.srv.url(&format!("/notes/v{v}")),
                "assets": files.iter().map(|(n, _)| serde_json::json!({
                    "name": n, "browser_download_url": self.srv.url(&format!("/dl/{n}")), "size": 1
                })).collect::<Vec<_>>()
            });
            self.srv.put("/latest", doc.to_string());
        }

        fn env(&self, app: &str, kind: Option<Kind>, inst: Result<Installation, NotHere>) -> Env {
            let started = self.started.clone();
            Env {
                http: Arc::new(NetHttp),
                feed: Url::parse(&self.srv.url("/latest")).unwrap(),
                pubkey: self.key.public.clone(),
                cosign: Arc::new(|| None),
                app_version: Version::parse(app).unwrap(),
                os: "macos".into(),
                arch: "aarch64".into(),
                kind,
                download_root: self.dir.join("downloads"),
                config_dir: self.dir.join("config"),
                installation: Arc::new(move || inst.clone()),
                start: Arc::new(
                    move |k: &Kind, files: &[PathBuf], digests: &[String], _log: &mut dyn FnMut(&str)| {
                        assert_eq!(files.len(), digests.len());
                        // The files exist and are the verified ones when started.
                        for f in files {
                            assert!(f.is_file());
                        }
                        started.lock().unwrap().push((k.clone(), files.to_vec()));
                        Ok(String::new())
                    },
                ),
            }
        }
    }

    #[test]
    fn manual_check_reports_newer_latest_and_offline_once() {
        claims::partial(&["FR-20.11"]);
        let f = Fixture::new("check");
        f.publish("1.4.0");
        let u = Updates::new(f.env("1.3.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled)));
        let now = SystemTime::now();
        assert_eq!(u.check(true, now), Some(Version::new(1, 4, 0)));
        let v = u.view();
        assert_eq!(v.phase, "available");
        assert_eq!(v.latest.as_deref(), Some("1.4.0"));
        assert_eq!(u.notes_url().unwrap().as_str(), f.srv.url("/notes/v1.4.0"));
        assert!(
            !u.auto_due(true, now + Duration::from_secs(60)),
            "the check was recorded"
        );
        assert!(u.auto_due(true, now + release::CHECK_INTERVAL));
        assert!(!u.auto_due(false, now + release::CHECK_INTERVAL));

        // Already on the newest version: UPDATES_NONE in the window.
        let u = Updates::new(f.env("1.4.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled)));
        assert_eq!(u.check(true, now), None);
        assert_eq!(u.view().phase, "latest");
        assert_eq!(u.view().latest.as_deref(), Some("1.4.0"));
        assert!(u.notes_url().is_none());

        // Offline: one UPDATE_CHECK_FAILED on demand, nothing automatic.
        let mut env = f.env("1.3.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled));
        env.feed = Url::parse("http://127.0.0.1:1/latest").unwrap();
        let u = Updates::new(env);
        assert_eq!(u.check(false, now), None);
        assert_eq!(u.view().phase, "idle");
        assert!(u.view().message.is_none());
        u.check(true, now);
        let m = u.view().message.unwrap();
        assert_eq!(m.code, "UPDATE_CHECK_FAILED");
        assert!(m.details.contains("127.0.0.1:1"));
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn app_update_verifies_then_starts_the_installer_of_its_kind() {
        claims::partial(&["FR-20.13", "SR-7-2"]);
        let f = Fixture::new("app");
        f.publish("1.4.0");
        let u = Updates::new(f.env("1.3.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled)));
        u.check(true, SystemTime::now());
        assert_eq!(u.update_app(), Some(Kind::MacPkg));
        assert_eq!(u.view().phase, "installer-started");
        let started = f.started.lock().unwrap().clone();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].0, Kind::MacPkg);
        assert!(started[0].1[0].ends_with("smcp_1.4.0_darwin_arm64.pkg"));
        assert!(u.view().log.iter().any(|l| l.starts_with("Verified:")));

        // A tampered installer: refused, named, nothing started.
        f.started.lock().unwrap().clear();
        f.srv.put("/dl/smcp_1.4.0_darwin_arm64.pkg", "tampered");
        let u = Updates::new(f.env("1.3.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled)));
        u.check(true, SystemTime::now());
        assert_eq!(u.update_app(), None);
        let m = u.view().message.unwrap();
        assert_eq!(m.code, "UPDATE_VERIFY_FAILED");
        assert_eq!(m.params["check"], "SHA-256 checksum");
        assert!(f.started.lock().unwrap().is_empty());

        // A build without a release version does not update itself, even
        // from a known installer.
        let u = Updates::new(f.env("0.1.0", Some(Kind::MacPkg), Err(NotHere::NotInstalled)));
        u.check(true, SystemTime::now());
        assert!(u.view().app_blocked.unwrap().contains("no release version (0.1.0)"));
        assert_eq!(u.update_app(), None);
        assert!(f.started.lock().unwrap().is_empty());

        // A build from source does not update itself.
        let u = Updates::new(f.env("1.3.0", None, Err(NotHere::NotInstalled)));
        u.check(true, SystemTime::now());
        assert!(u.view().app_blocked.is_some());
        assert_eq!(u.update_app(), None);
        assert!(f.started.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    /// FR-20.12 with a stand-in smcpctl: the Gateway is upgraded through
    /// `smcpctl upgrade` with the verified release directory, and a
    /// rollback is reported as a failed upgrade with the running version.
    #[cfg(unix)]
    #[test]
    fn gateway_upgrade_runs_smcpctl_and_reports_a_rollback() {
        claims::partial(&["FR-20.12", "SR-7-2"]);
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("gw");
        f.publish("1.4.0");
        let bin = f.dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let state = f.dir.join("version");
        std::fs::write(&state, "1.3.0\n").unwrap();
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = version ]; then cat "{state}"; exit 0; fi
IFS= read -r pass
rel="$5"
ls "$rel" > "{seen}"
echo "upgrade: upgrading from 1.3.0 to 1.4.0"
if [ "$pass" = bad ]; then echo "smcpctl: upgrade rolled back: migration failed; the previous version is running" >&2; exit 1; fi
echo 1.4.0 > "{state}"
echo "upgrade: upgrade complete"
"#,
            state = state.display(),
            seen = f.dir.join("seen").display()
        );
        std::fs::write(bin.join("smcpctl"), script).unwrap();
        std::fs::set_permissions(bin.join("smcpctl"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let inst = Installation {
            bin_dir: bin.clone(),
            config: f.dir.join("c.toml"),
        };

        // The app is current (1.4.0), the Gateway is older: offered.
        let u = Updates::new(f.env("1.4.0", Some(Kind::MacPkg), Ok(inst.clone())));
        u.check(true, SystemTime::now());
        let v = u.view();
        assert_eq!(v.gateway.as_deref(), Some("1.3.0"));
        assert!(v.gateway_upgradable);
        assert_eq!(v.phase, "available");

        match u.upgrade_gateway("bad").unwrap() {
            Outcome::RolledBack { running } => assert_eq!(running, "1.3.0"),
            o => panic!("{o:?}"),
        }
        let m = u.view().message.unwrap();
        assert_eq!(m.code, "UPGRADE_ROLLED_BACK");
        assert_eq!(m.params["version"], "1.3.0");
        assert!(!m.details.contains("bad"), "the passphrase is not in the details");
        let seen = std::fs::read_to_string(f.dir.join("seen")).unwrap();
        assert!(seen.contains("smcp_1.4.0_checksums.txt.minisig") && seen.contains("smcp_1.4.0_darwin_arm64.tar.gz"));

        assert_eq!(
            u.upgrade_gateway("good").unwrap(),
            Outcome::Upgraded {
                from: "1.3.0".into(),
                to: "1.4.0".into()
            }
        );
        assert_eq!(u.view().phase, "upgraded");
        assert_eq!(u.view().gateway.as_deref(), Some("1.4.0"));

        // Now current: a further upgrade of the same release is refused
        // as not newer, and smcpctl does not run.
        std::fs::remove_file(f.dir.join("seen")).unwrap();
        u.upgrade_gateway("good");
        assert_eq!(u.view().message.unwrap().code, "UPDATE_NOT_NEWER");
        assert!(!f.dir.join("seen").exists());

        // Enforced: not upgraded here, with the terminal command.
        let u = Updates::new(f.env("1.4.0", None, Err(NotHere::Enforced)));
        u.check(true, SystemTime::now());
        assert!(!u.view().gateway_upgradable);
        assert!(u.view().gateway_blocked.unwrap().contains("sudo smcpctl upgrade"));
        std::fs::remove_dir_all(&f.dir).unwrap();
    }

    #[test]
    fn every_message_code_is_in_the_catalogue() {
        claims::partial(&["FR-20.47", "FR-20.48"]);
        let cat: serde_json::Value = serde_json::from_str(include_str!("../../../docs/design/messages.json")).unwrap();
        let src = include_str!("updates.rs");
        let code_part = src.split("#[cfg(test)]\nmod tests").next().unwrap();
        let mut n = 0;
        for (i, _) in code_part
            .match_indices("message(\n")
            .chain(code_part.match_indices("message(\""))
        {
            let rest = &code_part[i..];
            let q = rest.find('"').unwrap();
            let code: String = rest[q + 1..].chars().take_while(|c| *c != '"').collect();
            let e = &cat["desktop"]["errors"][&code];
            assert!(e.is_object(), "{code} is not in docs/design/messages.json");
            for part in ["title", "what", "todo"] {
                assert!(e[part].is_string(), "{code} has no {part}");
            }
            n += 1;
        }
        assert!(n >= 6, "only {n} message codes found");
    }
}
