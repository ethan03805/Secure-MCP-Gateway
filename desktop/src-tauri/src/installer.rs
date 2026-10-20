//! Desktop application update (SRS FR-20.13, SR-7-2, SR-2-7).
//!
//! The application updates itself only with the release's platform
//! installer of the kind that installed it (FR-20.17 to FR-20.20), after
//! `verify` has checked the release, and never through the Tauri updater
//! plugin or any channel other than the release's signed checksum file.
//! This module decides the installation kind, picks the release files for
//! it, and starts the installer with a fixed argument vector. Elevation is
//! asked only by the installer itself or, for the Linux packages, by
//! `pkexec`, which names the command in its prompt (SR-2-7).
//!
//! On Linux the verified `.deb` or `.rpm` is handed to the package manager
//! as a sealed in-memory file, so a process running as the user cannot
//! change it between the check and the root-run install. On macOS and
//! Windows the verified file is opened from the private download directory;
//! that residual window is recorded in `docs/security-limitations.md`.

use std::path::{Path, PathBuf};

use semver::Version;

use crate::release::Asset;

/// How the running application was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// The macOS `.pkg` (application in `/Applications`, commands linked
    /// into `/usr/local/bin`).
    MacPkg,
    /// The macOS `.dmg` (application copied by hand).
    MacDmg,
    /// The Linux `smcp` and `smcp-desktop` `.deb` packages.
    Deb,
    /// The Linux `smcp` and `smcp-desktop` `.rpm` packages.
    Rpm,
    /// The Linux AppImage at this path.
    AppImage(PathBuf),
    /// The Windows `.msi`.
    Msi,
}

impl Kind {
    /// The name shown to the user.
    pub fn label(&self) -> &'static str {
        match self {
            Kind::MacPkg => "macOS package (.pkg)",
            Kind::MacDmg => "disk image (.dmg)",
            Kind::Deb => "Debian package (.deb)",
            Kind::Rpm => "RPM package (.rpm)",
            Kind::AppImage(_) => "AppImage",
            Kind::Msi => "Windows installer (.msi)",
        }
    }

    /// Whether the application quits after starting the installer, so the
    /// installer can replace it. The Linux package managers and the
    /// AppImage replacement finish first; the application then restarts.
    pub fn quits_after_start(&self) -> bool {
        matches!(self, Kind::MacPkg | Kind::MacDmg | Kind::Msi)
    }
}

/// What `detect` looks at, gathered by `Probe::current`.
#[derive(Debug, Clone, Default)]
pub struct Probe {
    pub os: String,
    /// The running executable, symbolic links resolved.
    pub exe: PathBuf,
    /// `$APPIMAGE`, set by the AppImage runtime.
    pub appimage: Option<PathBuf>,
    /// Where `/usr/local/bin/smcpctl` points, resolved (macOS `.pkg`).
    pub usr_local_smcpctl: Option<PathBuf>,
    /// dpkg's file list of `smcp-desktop` exists.
    pub dpkg_owned: bool,
    /// The rpm database tool exists.
    pub rpm_present: bool,
}

impl Probe {
    pub fn current() -> Probe {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .unwrap_or_default();
        Probe {
            os: std::env::consts::OS.into(),
            exe,
            appimage: std::env::var_os("APPIMAGE")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute() && p.is_file()),
            usr_local_smcpctl: std::fs::canonicalize("/usr/local/bin/smcpctl").ok(),
            dpkg_owned: Path::new("/var/lib/dpkg/info/smcp-desktop.list").is_file(),
            rpm_present: Path::new("/usr/bin/rpm").is_file(),
        }
    }
}

/// The application bundle (`.../Name.app`) that contains `exe`.
fn app_bundle(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

/// Decides how the running application was installed; `None` for a build
/// from source or a layout no installer makes, which is not updated from
/// the application.
pub fn detect(p: &Probe) -> Option<Kind> {
    match p.os.as_str() {
        "macos" => {
            let bundle = app_bundle(&p.exe)?;
            // The .pkg installs the bundle in /Applications and links the
            // commands inside it into /usr/local/bin.
            let linked = p.usr_local_smcpctl.as_ref().is_some_and(|t| t.starts_with(&bundle));
            if bundle.parent() == Some(Path::new("/Applications")) && linked {
                Some(Kind::MacPkg)
            } else {
                Some(Kind::MacDmg)
            }
        }
        "linux" => {
            if let Some(a) = &p.appimage {
                return Some(Kind::AppImage(a.clone()));
            }
            if !p.exe.starts_with("/usr") {
                return None;
            }
            if p.dpkg_owned {
                Some(Kind::Deb)
            } else if p.rpm_present {
                Some(Kind::Rpm)
            } else {
                None
            }
        }
        "windows" => {
            let s = p.exe.to_string_lossy().to_ascii_lowercase();
            s.contains("\\program files\\").then_some(Kind::Msi)
        }
        _ => None,
    }
}

fn arch_tokens(kind: &Kind, arch: &str) -> &'static [&'static str] {
    match (kind, arch) {
        (Kind::Deb, "x86_64") => &["amd64"],
        (Kind::Deb, "aarch64") => &["arm64"],
        (Kind::Rpm, "x86_64") => &["x86_64"],
        (Kind::Rpm, "aarch64") => &["aarch64"],
        (Kind::AppImage(_), "x86_64") => &["amd64", "x86_64"],
        (Kind::AppImage(_), "aarch64") => &["arm64", "aarch64"],
        (Kind::MacPkg | Kind::MacDmg, "aarch64") => &["arm64", "aarch64"],
        (Kind::Msi, "x86_64") => &["x64", "amd64"],
        (Kind::Msi, "aarch64") => &["arm64"],
        _ => &[],
    }
}

/// The release files this installation needs, in install order. Names
/// follow the release's asset names (`release.yml`, FR-20.17 to FR-20.20);
/// each must carry the release version, and exactly one file may match each
/// slot.
pub fn files_for(kind: &Kind, v: &Version, arch: &str, assets: &[Asset]) -> Result<Vec<String>, String> {
    let tokens = arch_tokens(kind, arch);
    if tokens.is_empty() {
        return Err(format!("no {} for this processor ({arch})", kind.label()));
    }
    let ver = v.to_string();
    // The token stands alone: not part of a longer word (x64 is not in
    // x86_64, arm64 is not in aarch64).
    let has_arch = |n: &str| {
        tokens.iter().any(|t| {
            n.match_indices(t).any(|(i, _)| {
                let before = n[..i].chars().next_back();
                let after = n[i + t.len()..].chars().next();
                !before.is_some_and(|c| c.is_ascii_alphanumeric()) && !after.is_some_and(|c| c.is_ascii_alphanumeric())
            })
        })
    };
    let pick = |what: &str, f: &dyn Fn(&str) -> bool| -> Result<String, String> {
        let m: Vec<&Asset> = assets.iter().filter(|a| a.name.contains(&ver) && f(&a.name)).collect();
        match m.as_slice() {
            [one] => Ok(one.name.clone()),
            [] => Err(format!("release {ver} has no {what}")),
            _ => Err(format!(
                "release {ver} has more than one {what}: {}",
                m.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    };
    let desktop = |n: &str| n.starts_with("smcp-desktop");
    Ok(match kind {
        Kind::MacPkg => vec![pick("macOS package", &|n| {
            n.starts_with("smcp_") && n.ends_with(".pkg") && has_arch(n)
        })?],
        Kind::MacDmg => vec![pick("disk image", &|n| n.ends_with(".dmg") && has_arch(n))?],
        Kind::Deb => vec![
            pick("smcp .deb", &|n| {
                n.starts_with("smcp_") && n.ends_with(".deb") && has_arch(n)
            })?,
            pick("smcp-desktop .deb", &|n| {
                desktop(n) && n.ends_with(".deb") && has_arch(n)
            })?,
        ],
        Kind::Rpm => vec![
            pick("smcp .rpm", &|n| {
                n.starts_with(&format!("smcp-{ver}")) && n.ends_with(".rpm") && has_arch(n)
            })?,
            pick("smcp-desktop .rpm", &|n| {
                desktop(n) && n.ends_with(".rpm") && has_arch(n)
            })?,
        ],
        Kind::AppImage(_) => vec![pick("AppImage", &|n| n.ends_with(".AppImage") && has_arch(n))?],
        // The smcp-desktop .msi carries the commands too (FR-20.20); the
        // smcp .msi of the same release is for hosts without the app.
        Kind::Msi => vec![pick("smcp-desktop Windows installer", &|n| {
            desktop(n) && n.ends_with(".msi") && has_arch(n)
        })?],
    })
}

const OPEN: &str = "/usr/bin/open";
const PKEXEC: &str = "/usr/bin/pkexec";
const DPKG: &str = "/usr/bin/dpkg";
const RPM: &str = "/usr/bin/rpm";
const MSIEXEC: &str = "C:\\Windows\\System32\\msiexec.exe";

/// The fixed argument vector that starts the installer for `files`
/// (paths, in the order of `files_for`). `None` for the AppImage, which is
/// replaced in place instead.
pub fn start_argv(kind: &Kind, files: &[PathBuf]) -> Option<Vec<String>> {
    let f: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    let mut v: Vec<String> = match kind {
        // Installer.app and the Finder ask for what they need.
        Kind::MacPkg | Kind::MacDmg => vec![OPEN.into()],
        // pkexec names the command in the polkit prompt. dpkg and rpm
        // install exactly these files, offline; rpm -U never downgrades.
        Kind::Deb => vec![PKEXEC.into(), DPKG.into(), "-i".into()],
        Kind::Rpm => vec![PKEXEC.into(), RPM.into(), "-U".into()],
        // The installer shows the User Account Control prompt itself.
        Kind::Msi => vec![MSIEXEC.into(), "/i".into()],
        Kind::AppImage(_) => return None,
    };
    v.extend(f);
    Some(v)
}

/// Replaces the AppImage at `target` with the verified `new` file: copied
/// beside it, made executable, renamed over it. The running copy keeps its
/// open file until the application restarts.
pub fn replace_appimage(new: &Path, target: &Path) -> std::io::Result<()> {
    let dir = target
        .parent()
        .ok_or_else(|| std::io::Error::other("the AppImage has no directory"))?;
    let tmp = dir.join(format!(
        ".{}.update",
        target
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_file(&tmp);
    std::fs::copy(new, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, target)
}

/// A verified file sealed in memory (Linux): its content cannot change
/// after the check, even for a process running as the same user.
#[cfg(target_os = "linux")]
pub mod sealed {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::path::{Path, PathBuf};

    pub struct Sealed {
        file: File,
        pub sha256: String,
    }

    impl Sealed {
        /// Copies `src` into a sealed memfd and returns it with the SHA-256
        /// of what was sealed. The caller compares that digest with the
        /// checksum file, so the check and the install read the same bytes.
        pub fn from_file(src: &Path, name: &str) -> std::io::Result<Sealed> {
            let cname = std::ffi::CString::new(name).map_err(std::io::Error::other)?;
            // SAFETY: memfd_create takes a valid C string and flags.
            let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_ALLOW_SEALING) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: fd is a new descriptor that this File now owns.
            let mut file = unsafe { File::from_raw_fd(fd) };
            let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
            let mut input = File::open(src)?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                ctx.update(&buf[..n]);
                file.write_all(&buf[..n])?;
            }
            let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
            // SAFETY: fcntl on a descriptor we own.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            file.seek(SeekFrom::Start(0))?;
            let sha256 = ctx.finish().as_ref().iter().map(|b| format!("{b:02x}")).collect();
            Ok(Sealed { file, sha256 })
        }

        /// A path through which root (the package manager under pkexec)
        /// opens the sealed content while this process holds it.
        pub fn path(&self) -> PathBuf {
            PathBuf::from(format!("/proc/{}/fd/{}", std::process::id(), self.file.as_raw_fd()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    fn assets(names: &[&str]) -> Vec<Asset> {
        names
            .iter()
            .map(|n| Asset {
                name: n.to_string(),
                url: url::Url::parse(&format!("https://example.com/{n}")).unwrap(),
                size: 1,
            })
            .collect()
    }

    const RELEASE: &[&str] = &[
        "smcp_1.4.0_checksums.txt",
        "smcp_1.4.0_checksums.txt.minisig",
        "smcp_1.4.0_darwin_arm64.tar.gz",
        "smcp_1.4.0_darwin_arm64.pkg",
        "smcp-desktop_1.4.0_darwin_arm64.dmg",
        "smcp_1.4.0_amd64.deb",
        "smcp_1.4.0_arm64.deb",
        "smcp-desktop_1.4.0_amd64.deb",
        "smcp-desktop_1.4.0_arm64.deb",
        "smcp-1.4.0-1.x86_64.rpm",
        "smcp-1.4.0-1.aarch64.rpm",
        "smcp-desktop-1.4.0-1.x86_64.rpm",
        "smcp-desktop-1.4.0-1.aarch64.rpm",
        "smcp-desktop_1.4.0_amd64.AppImage",
        "smcp-desktop_1.4.0_aarch64.AppImage",
        "smcp_1.4.0_windows_amd64.msi",
        "smcp_1.4.0_windows_arm64.msi",
        "smcp-desktop_1.4.0_windows_amd64.msi",
        "smcp-desktop_1.4.0_windows_arm64.msi",
    ];

    #[test]
    fn picks_the_installer_of_the_kind_that_installed_the_app() {
        claims::partial(&["FR-20.13"]);
        let a = assets(RELEASE);
        let v = Version::new(1, 4, 0);
        let f = |k: &Kind, arch: &str| files_for(k, &v, arch, &a).unwrap();
        assert_eq!(f(&Kind::MacPkg, "aarch64"), ["smcp_1.4.0_darwin_arm64.pkg"]);
        assert_eq!(f(&Kind::MacDmg, "aarch64"), ["smcp-desktop_1.4.0_darwin_arm64.dmg"]);
        assert_eq!(
            f(&Kind::Deb, "x86_64"),
            ["smcp_1.4.0_amd64.deb", "smcp-desktop_1.4.0_amd64.deb"]
        );
        assert_eq!(
            f(&Kind::Deb, "aarch64"),
            ["smcp_1.4.0_arm64.deb", "smcp-desktop_1.4.0_arm64.deb"]
        );
        assert_eq!(
            f(&Kind::Rpm, "x86_64"),
            ["smcp-1.4.0-1.x86_64.rpm", "smcp-desktop-1.4.0-1.x86_64.rpm"]
        );
        assert_eq!(
            f(&Kind::AppImage("/x".into()), "aarch64"),
            ["smcp-desktop_1.4.0_aarch64.AppImage"]
        );
        // The smcp-desktop .msi, never the smcp one (FR-20.20), for both
        // Windows architectures.
        assert_eq!(f(&Kind::Msi, "x86_64"), ["smcp-desktop_1.4.0_windows_amd64.msi"]);
        assert_eq!(f(&Kind::Msi, "aarch64"), ["smcp-desktop_1.4.0_windows_arm64.msi"]);
        // No Intel macOS application (FR-20.1), no file of another version,
        // and an ambiguous release is refused.
        assert!(files_for(&Kind::MacPkg, &v, "x86_64", &a).is_err());
        assert!(files_for(&Kind::MacPkg, &Version::new(1, 5, 0), "aarch64", &a).is_err());
        let mut two = RELEASE.to_vec();
        two.push("smcp-desktop_1.4.0_amd64_extra.AppImage");
        assert!(files_for(&Kind::AppImage("/x".into()), &v, "x86_64", &assets(&two))
            .unwrap_err()
            .contains("more than one"));
    }

    #[test]
    fn detects_the_installation_kind() {
        claims::partial(&["FR-20.13"]);
        let mac = |exe: &str, link: Option<&str>| Probe {
            os: "macos".into(),
            exe: exe.into(),
            usr_local_smcpctl: link.map(PathBuf::from),
            ..Default::default()
        };
        let app = "/Applications/Secure MCP Gateway.app/Contents/MacOS/smcp-desktop";
        assert_eq!(
            detect(&mac(
                app,
                Some("/Applications/Secure MCP Gateway.app/Contents/MacOS/smcpctl")
            )),
            Some(Kind::MacPkg)
        );
        assert_eq!(detect(&mac(app, None)), Some(Kind::MacDmg));
        assert_eq!(
            detect(&mac(
                "/Users/a/Downloads/Secure MCP Gateway.app/Contents/MacOS/smcp-desktop",
                None
            )),
            Some(Kind::MacDmg)
        );
        assert_eq!(detect(&mac("/Users/a/src/target/release/smcp-desktop", None)), None);

        let linux = |exe: &str, appimage: Option<&str>, dpkg: bool, rpm: bool| Probe {
            os: "linux".into(),
            exe: exe.into(),
            appimage: appimage.map(PathBuf::from),
            dpkg_owned: dpkg,
            rpm_present: rpm,
            ..Default::default()
        };
        assert_eq!(
            detect(&linux(
                "/tmp/.mount_x/usr/bin/smcp-desktop",
                Some("/home/a/smcp.AppImage"),
                false,
                false
            )),
            Some(Kind::AppImage("/home/a/smcp.AppImage".into()))
        );
        assert_eq!(
            detect(&linux("/usr/bin/smcp-desktop", None, true, true)),
            Some(Kind::Deb)
        );
        assert_eq!(
            detect(&linux("/usr/bin/smcp-desktop", None, false, true)),
            Some(Kind::Rpm)
        );
        assert_eq!(
            detect(&linux("/home/a/target/release/smcp-desktop", None, true, true)),
            None
        );

        let win = Probe {
            os: "windows".into(),
            exe: "C:\\Program Files\\Secure MCP Gateway\\smcp-desktop.exe".into(),
            ..Default::default()
        };
        assert_eq!(detect(&win), Some(Kind::Msi));
    }

    #[test]
    fn start_argv_is_fixed_and_elevates_only_the_package_manager() {
        claims::partial(&["FR-20.13", "SR-2-7"]);
        let f = |n: &[&str]| n.iter().map(PathBuf::from).collect::<Vec<_>>();
        assert_eq!(
            start_argv(&Kind::MacPkg, &f(&["/d/smcp_1.4.0_darwin_arm64.pkg"])).unwrap(),
            ["/usr/bin/open", "/d/smcp_1.4.0_darwin_arm64.pkg"]
        );
        assert_eq!(
            start_argv(&Kind::Deb, &f(&["/proc/1/fd/7", "/proc/1/fd/8"])).unwrap(),
            ["/usr/bin/pkexec", "/usr/bin/dpkg", "-i", "/proc/1/fd/7", "/proc/1/fd/8"]
        );
        assert_eq!(
            start_argv(&Kind::Rpm, &f(&["/a.rpm", "/b.rpm"])).unwrap(),
            ["/usr/bin/pkexec", "/usr/bin/rpm", "-U", "/a.rpm", "/b.rpm"]
        );
        assert_eq!(
            start_argv(&Kind::Msi, &f(&["C:\\d\\a.msi"])).unwrap(),
            ["C:\\Windows\\System32\\msiexec.exe", "/i", "C:\\d\\a.msi"]
        );
        assert_eq!(start_argv(&Kind::AppImage("/x".into()), &f(&["/a"])), None);
        // No downgrade flags.
        for k in [Kind::Deb, Kind::Rpm] {
            let a = start_argv(&k, &f(&["/a"])).unwrap().join(" ");
            assert!(!a.contains("oldpackage") && !a.contains("force"), "{a}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn appimage_is_replaced_atomically_and_executable() {
        claims::partial(&["FR-20.13"]);
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("smcp-desktop-appimage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("app.AppImage"), "old").unwrap();
        std::fs::write(d.join("new"), "new").unwrap();
        replace_appimage(&d.join("new"), &d.join("app.AppImage")).unwrap();
        assert_eq!(std::fs::read_to_string(d.join("app.AppImage")).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(d.join("app.AppImage")).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2, "no temporary file left");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The sealed copy reads back the verified bytes through its /proc
    /// path and refuses every write, so the file the package manager
    /// installs is the file that was checked.
    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_copy_cannot_be_changed() {
        claims::partial(&["SR-7-2"]);
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("smcp-desktop-sealed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.deb"), b"package bytes").unwrap();
        let s = sealed::Sealed::from_file(&d.join("a.deb"), "a.deb").unwrap();
        assert_eq!(s.sha256, crate::verify::sha256(b"package bytes"));
        // Changing the source afterwards does not change the sealed copy.
        std::fs::write(d.join("a.deb"), b"changed").unwrap();
        assert_eq!(std::fs::read(s.path()).unwrap(), b"package bytes");
        let w = std::fs::OpenOptions::new().write(true).open(s.path());
        if let Ok(mut f) = w {
            assert!(f.write_all(b"x").is_err(), "a sealed file accepted a write");
        }
        assert_eq!(std::fs::read(s.path()).unwrap(), b"package bytes");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
