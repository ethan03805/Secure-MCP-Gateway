//! Desktop preferences (E-34 owned data): where the Gateway's admin
//! listener and metrics endpoint are, which CA bundle the console window
//! trusts, and whether approval notifications are on. No credentials are
//! stored here or anywhere else by the application (SR-2-4); the
//! application never reads the Gateway configuration, the operator token,
//! the Secret Vault or the key store (SR-2-3), so the addresses are its own
//! settings, defaulting to CP-03 and CP-51.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

/// CP-03 admin listener.
pub const DEFAULT_ADMIN_URL: &str = "https://127.0.0.1:8444";
/// CP-51 metrics endpoint.
pub const DEFAULT_METRICS_ADDRESS: &str = "127.0.0.1:9464";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// The admin listener's URL (scheme, host and port only).
    pub admin_url: String,
    /// The metrics endpoint's loopback address.
    pub metrics_address: String,
    /// The Gateway CA bundle; empty means the Standalone default.
    pub ca_file: String,
    /// Approval notifications (FR-20.7).
    pub notifications: bool,
    /// Start the application at login (FR-20.14); off after installation.
    pub start_at_login: bool,
    /// Automatic update checks, at most once every 24 hours (FR-20.11).
    /// Off, the application checks only when Check for Updates is selected.
    pub update_checks: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            admin_url: DEFAULT_ADMIN_URL.into(),
            metrics_address: DEFAULT_METRICS_ADDRESS.into(),
            ca_file: String::new(),
            notifications: true,
            start_at_login: false,
            update_checks: true,
        }
    }
}

/// A rejected field, for the settings window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    pub field: &'static str,
    pub message: String,
}

/// The admin listener's origin, the only origin the console window loads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminOrigin {
    pub host: String,
    pub port: u16,
}

impl AdminOrigin {
    /// Accepts `https://host[:port][/]` and nothing else: no user
    /// information, path, query or fragment.
    pub fn parse(s: &str) -> Result<AdminOrigin, String> {
        let u = Url::parse(s.trim()).map_err(|e| format!("not a URL: {e}"))?;
        if u.scheme() != "https" {
            return Err("the admin listener is served over HTTPS only (CP-03)".into());
        }
        if !u.username().is_empty() || u.password().is_some() {
            return Err("the URL must not contain a user name or password".into());
        }
        if u.path() != "/" || u.query().is_some() || u.fragment().is_some() {
            return Err("give the listener's address only, without a path".into());
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return Err("the URL has no host".into()),
        };
        Ok(AdminOrigin {
            host,
            port: u.port_or_known_default().unwrap_or(443),
        })
    }

    /// The URL host as it appears in a URL (IPv6 in brackets).
    fn url_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    /// The console page at `path` on this origin.
    pub fn page(&self, path: &str) -> Url {
        Url::parse(&format!("https://{}:{}{}", self.url_host(), self.port, path)).expect("valid origin")
    }

    /// Whether `u` is on this origin (scheme, host and port).
    pub fn contains(&self, u: &Url) -> bool {
        if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() {
            return false;
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            None => return false,
        };
        host.eq_ignore_ascii_case(&self.host) && u.port_or_known_default() == Some(self.port)
    }
}

/// Settings checked and resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub admin: AdminOrigin,
    pub metrics: SocketAddr,
    pub ca_file: PathBuf,
    pub notifications: bool,
}

/// The CA certificate an Enforced installation publishes for users (CP-46
/// `public/`): the state directory is closed to them, so `smcpd` copies its
/// trust bundle here, readable by everyone (the certificate is public).
pub const ENFORCED_CA_FILE: &str = "/var/lib/smcp/public/ca.crt";

/// The CA bundle the console window trusts when Settings name none: the
/// Standalone `<state dir>/tls/ca.crt` of CP-46 on this platform, or on
/// Linux, when that file does not exist and an Enforced installation has
/// published its CA certificate, that copy.
pub fn default_ca_file(os: &str, home: &Path, xdg_state_home: Option<&Path>) -> PathBuf {
    default_ca_file_in(os, home, xdg_state_home, Path::new(ENFORCED_CA_FILE))
}

/// [`default_ca_file`] with the Enforced copy's path given (tests).
pub fn default_ca_file_in(os: &str, home: &Path, xdg_state_home: Option<&Path>, enforced: &Path) -> PathBuf {
    match os {
        "macos" => home.join("Library/Application Support/smcp-gateway/state/tls/ca.crt"),
        // The per-user mode's state directory, %LOCALAPPDATA%\smcp-gateway\state.
        "windows" => home.join(r"AppData\Local\smcp-gateway\state\tls\ca.crt"),
        _ => {
            let standalone = xdg_state_home
                .filter(|p| p.is_absolute())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| home.join(".local/state"))
                .join("smcp-gateway/tls/ca.crt");
            if os == "linux" && !standalone.exists() && enforced.is_file() {
                enforced.to_path_buf()
            } else {
                standalone
            }
        }
    }
}

impl Settings {
    pub fn resolve(&self, os: &str, home: &Path, xdg_state_home: Option<&Path>) -> Result<Resolved, Vec<FieldError>> {
        let mut errs = Vec::new();
        let admin = AdminOrigin::parse(&self.admin_url)
            .map_err(|m| {
                errs.push(FieldError {
                    field: "admin_url",
                    message: m,
                })
            })
            .ok();
        let metrics = match self.metrics_address.trim().parse::<SocketAddr>() {
            Ok(a) if a.ip().is_loopback() && a.port() != 0 => Some(a),
            Ok(_) => {
                errs.push(FieldError {
                    field: "metrics_address",
                    message: "the metrics endpoint is a loopback address with a port (CP-51)".into(),
                });
                None
            }
            Err(_) => {
                errs.push(FieldError {
                    field: "metrics_address",
                    message: "give an address such as 127.0.0.1:9464".into(),
                });
                None
            }
        };
        let ca_file = if self.ca_file.trim().is_empty() {
            default_ca_file(os, home, xdg_state_home)
        } else {
            let p = PathBuf::from(self.ca_file.trim());
            if !p.is_absolute() {
                errs.push(FieldError {
                    field: "ca_file",
                    message: "give an absolute path".into(),
                });
            }
            p
        };
        match (admin, metrics, errs.is_empty()) {
            (Some(admin), Some(metrics), true) => Ok(Resolved {
                admin,
                metrics,
                ca_file,
                notifications: self.notifications,
            }),
            _ => Err(errs),
        }
    }

    /// Reads the settings file; a missing or unreadable file gives the
    /// defaults.
    pub fn load(path: &Path) -> Settings {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Writes the settings file atomically, readable by the user only.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            use std::io::Write;
            let mut f = o.open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims;

    #[test]
    fn admin_origin_is_https_origin_only() {
        claims::partial(&["FR-20.6", "SR-2-6"]);
        let o = AdminOrigin::parse("https://127.0.0.1:8444").unwrap();
        assert_eq!(
            o,
            AdminOrigin {
                host: "127.0.0.1".into(),
                port: 8444
            }
        );
        assert_eq!(o.page("/approvals").as_str(), "https://127.0.0.1:8444/approvals");
        assert_eq!(AdminOrigin::parse("https://localhost/").unwrap().port, 443);
        assert_eq!(
            AdminOrigin::parse("https://[::1]:8444").unwrap().page("/").as_str(),
            "https://[::1]:8444/"
        );
        for bad in [
            "http://127.0.0.1:8444",
            concat!("https://u:p", "@127.0.0.1:8444"),
            "https://127.0.0.1:8444/console",
            "https://127.0.0.1:8444/?x=1",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "127.0.0.1:8444",
        ] {
            assert!(AdminOrigin::parse(bad).is_err(), "{bad}");
        }
        for (u, inside) in [
            ("https://127.0.0.1:8444/approvals/123", true),
            ("https://127.0.0.1:8444/", true),
            ("https://127.0.0.1:8445/", false),
            ("http://127.0.0.1:8444/", false),
            (concat!("https://127.0.0.1:8444", "@evil.example/"), false),
            ("https://evil.example/?https://127.0.0.1:8444", false),
            ("https://127.0.0.1.evil.example:8444/", false),
            ("wss://127.0.0.1:8444/", false),
        ] {
            assert_eq!(o.contains(&Url::parse(u).unwrap()), inside, "{u}");
        }
    }

    #[test]
    fn defaults_are_cp03_and_cp51_and_metrics_must_be_loopback() {
        claims::partial(&["FR-20.4"]);
        let home = Path::new("/home/u");
        let r = Settings::default().resolve("linux", home, None).unwrap();
        assert_eq!(
            r.admin,
            AdminOrigin {
                host: "127.0.0.1".into(),
                port: 8444
            }
        );
        assert_eq!(r.metrics, "127.0.0.1:9464".parse().unwrap());
        assert_eq!(r.ca_file, PathBuf::from("/home/u/.local/state/smcp-gateway/tls/ca.crt"));
        assert!(r.notifications);
        let mac = Settings::default()
            .resolve("macos", Path::new("/Users/u"), None)
            .unwrap();
        assert_eq!(
            mac.ca_file,
            PathBuf::from("/Users/u/Library/Application Support/smcp-gateway/state/tls/ca.crt")
        );
        assert_eq!(
            default_ca_file("linux", home, Some(Path::new("/x/state"))),
            PathBuf::from("/x/state/smcp-gateway/tls/ca.crt")
        );

        // Linux Enforced: the state directory is closed to the user, so the
        // CA certificate the Gateway publishes is the default, unless a
        // Standalone CA exists for this user.
        let dir = std::env::temp_dir().join(format!("smcp-settings-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let published = dir.join("public/ca.crt");
        let state = dir.join("state");
        let standalone = state.join("smcp-gateway/tls/ca.crt");
        assert_eq!(
            default_ca_file_in("linux", home, Some(&state), &published),
            standalone,
            "nothing published: the Standalone path"
        );
        std::fs::create_dir_all(published.parent().unwrap()).unwrap();
        std::fs::write(&published, "ca").unwrap();
        assert_eq!(default_ca_file_in("linux", home, Some(&state), &published), published);
        assert_eq!(
            default_ca_file_in("macos", home, Some(&state), &published),
            home.join("Library/Application Support/smcp-gateway/state/tls/ca.crt")
        );
        std::fs::create_dir_all(standalone.parent().unwrap()).unwrap();
        std::fs::write(&standalone, "ca").unwrap();
        assert_eq!(default_ca_file_in("linux", home, Some(&state), &published), standalone);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(ENFORCED_CA_FILE, "/var/lib/smcp/public/ca.crt");
        let bad = Settings {
            admin_url: "http://x".into(),
            metrics_address: "192.0.2.1:9464".into(),
            ca_file: "rel/ca.crt".into(),
            notifications: false,
            start_at_login: false,
            update_checks: false,
        };
        let errs = bad.resolve("linux", home, None).unwrap_err();
        let fields: Vec<_> = errs.iter().map(|e| e.field).collect();
        assert_eq!(fields, ["admin_url", "metrics_address", "ca_file"]);
    }

    #[test]
    fn update_checks_default_on_and_older_files_load() {
        claims::partial(&["FR-20.11"]);
        assert!(Settings::default().update_checks);
        // A settings file written before the switch existed keeps it on.
        let old: Settings = serde_json::from_str(
            r#"{"admin_url":"https://127.0.0.1:8444","metrics_address":"127.0.0.1:9464","ca_file":"","notifications":false}"#,
        )
        .unwrap();
        assert!(old.update_checks);
        assert!(!old.notifications);
        let off: Settings = serde_json::from_str(r#"{"update_checks":false}"#).unwrap();
        assert!(!off.update_checks);
    }

    #[test]
    fn saved_settings_are_private_and_round_trip() {
        claims::partial(&["SR-2-4"]);
        let dir = std::env::temp_dir().join(format!("smcp-desktop-settings-{}", std::process::id()));
        let p = dir.join("settings.json");
        let s = Settings {
            admin_url: "https://127.0.0.1:9000".into(),
            notifications: false,
            ..Default::default()
        };
        s.save(&p).unwrap();
        assert_eq!(Settings::load(&p), s);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // The file holds addresses and switches only, never a credential.
        let body = std::fs::read_to_string(&p).unwrap();
        for word in ["password", "token", "cookie", "secret"] {
            assert!(!body.to_lowercase().contains(word), "{word}");
        }
        std::fs::write(&p, "{not json").unwrap();
        assert_eq!(Settings::load(&p), Settings::default());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
